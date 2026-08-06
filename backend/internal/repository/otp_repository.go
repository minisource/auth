package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/minisource/auth/internal/database"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
)

type OTPRepository interface {
	Create(ctx context.Context, otp *models.OTP) error
	GetByTarget(ctx context.Context, target, otpType string) (*models.OTP, error)
	IncrementAttempts(ctx context.Context, target, otpType string) error
	MarkUsed(ctx context.Context, target, otpType string) error
	Delete(ctx context.Context, target, otpType string) error
}

type otpRepositoryRedis struct {
	redis  *redis.Client
	logger logging.Logger
}

func NewOTPRepository(redis *redis.Client, logger logging.Logger) OTPRepository {
	return &otpRepositoryRedis{redis: redis, logger: logger}
}

func (r *otpRepositoryRedis) Create(ctx context.Context, otp *models.OTP) error {
	key := database.OTPKey(otp.Target, otp.Type)
	expiry := time.Until(otp.ExpiresAt)
	if expiry <= 0 {
		return fmt.Errorf("OTP already expired")
	}

	data, err := json.Marshal(otp)
	if err != nil {
		return fmt.Errorf("failed to marshal OTP: %w", err)
	}

	r.logger.Debug(logging.Redis, logging.Insert, "Storing OTP in Redis", map[logging.ExtraKey]interface{}{
		"key":       key,
		"target":    otp.Target,
		"code":      otp.Code,
		"type":      otp.Type,
		"expiresIn": expiry.Seconds(),
	})

	return r.redis.Set(ctx, key, data, expiry).Err()
}

func (r *otpRepositoryRedis) GetByTarget(ctx context.Context, target, otpType string) (*models.OTP, error) {
	key := database.OTPKey(target, otpType)
	r.logger.Debug(logging.Redis, logging.Select, "Getting OTP from Redis", map[logging.ExtraKey]interface{}{
		"key":     key,
		"target":  target,
		"otpType": otpType,
	})

	data, err := r.redis.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			r.logger.Debug(logging.Redis, logging.Select, "OTP not found in Redis (key does not exist)", map[logging.ExtraKey]interface{}{
				"key": key,
			})
			return nil, nil // OTP not found or expired
		}
		r.logger.Error(logging.Redis, logging.Select, "Redis error getting OTP", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
			"key":   key,
		})
		return nil, err
	}

	var otp models.OTP
	if err := json.Unmarshal([]byte(data), &otp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal OTP: %w", err)
	}

	// Check if expired or used
	if otp.IsUsed || time.Now().After(otp.ExpiresAt) {
		r.redis.Del(ctx, key)
		return nil, nil
	}

	return &otp, nil
}

func (r *otpRepositoryRedis) IncrementAttempts(ctx context.Context, target, otpType string) error {
	otp, err := r.GetByTarget(ctx, target, otpType)
	if err != nil || otp == nil {
		return err
	}

	otp.Attempts++
	return r.Create(ctx, otp)
}

func (r *otpRepositoryRedis) MarkUsed(ctx context.Context, target, otpType string) error {
	otp, err := r.GetByTarget(ctx, target, otpType)
	if err != nil || otp == nil {
		return err
	}

	otp.IsUsed = true
	now := time.Now()
	otp.UsedAt = &now

	// Save it briefly then delete
	key := database.OTPKey(target, otpType)
	data, err := json.Marshal(otp)
	if err != nil {
		return err
	}

	// Set with very short expiry since it's used
	r.redis.Set(ctx, key, data, 10*time.Second)
	return nil
}

func (r *otpRepositoryRedis) Delete(ctx context.Context, target, otpType string) error {
	key := database.OTPKey(target, otpType)
	return r.redis.Del(ctx, key).Err()
}
