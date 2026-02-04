package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/database"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
)

type RefreshTokenRepository interface {
	Create(ctx context.Context, token *models.RefreshToken) error
	GetByToken(ctx context.Context, token string) (*models.RefreshToken, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.RefreshToken, error)
	Revoke(ctx context.Context, token string) error
	RevokeByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpired(ctx context.Context) error
}

type refreshTokenRepository struct {
	redis  *redis.Client
	logger logging.Logger
}

func NewRefreshTokenRepository(redis *redis.Client, logger logging.Logger) RefreshTokenRepository {
	return &refreshTokenRepository{redis: redis, logger: logger}
}

func (r *refreshTokenRepository) Create(ctx context.Context, token *models.RefreshToken) error {
	// Store by token hash for fast lookup
	tokenKey := database.RefreshTokenKey(token.Token)
	expiry := time.Until(token.ExpiresAt)
	if expiry <= 0 {
		return fmt.Errorf("refresh token already expired")
	}

	data, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("failed to marshal refresh token: %w", err)
	}

	// Store token
	if err := r.redis.Set(ctx, tokenKey, data, expiry).Err(); err != nil {
		return err
	}

	// Add to user's token set for batch operations
	userTokensKey := fmt.Sprintf("%s%s", database.RedisKeyRefreshToken, token.UserID.String())
	r.redis.SAdd(ctx, userTokensKey, token.Token)
	r.redis.Expire(ctx, userTokensKey, expiry)

	return nil
}

func (r *refreshTokenRepository) GetByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	tokenKey := database.RefreshTokenKey(token)
	data, err := r.redis.Get(ctx, tokenKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Token not found or expired
		}
		return nil, err
	}

	var refreshToken models.RefreshToken
	if err := json.Unmarshal([]byte(data), &refreshToken); err != nil {
		return nil, fmt.Errorf("failed to unmarshal refresh token: %w", err)
	}

	// Check if expired or revoked
	if refreshToken.IsRevoked || time.Now().After(refreshToken.ExpiresAt) {
		r.redis.Del(ctx, tokenKey)
		return nil, nil
	}

	return &refreshToken, nil
}

func (r *refreshTokenRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*models.RefreshToken, error) {
	userTokensKey := fmt.Sprintf("%s%s", database.RedisKeyRefreshToken, userID.String())
	tokens, err := r.redis.SMembers(ctx, userTokensKey).Result()
	if err != nil {
		return nil, err
	}

	var refreshTokens []*models.RefreshToken
	for _, token := range tokens {
		rt, err := r.GetByToken(ctx, token)
		if err != nil {
			continue
		}
		if rt != nil {
			refreshTokens = append(refreshTokens, rt)
		}
	}

	return refreshTokens, nil
}

func (r *refreshTokenRepository) Revoke(ctx context.Context, token string) error {
	rt, err := r.GetByToken(ctx, token)
	if err != nil || rt == nil {
		return err
	}

	rt.IsRevoked = true
	now := time.Now()
	rt.RevokedAt = &now

	tokenKey := database.RefreshTokenKey(token)
	data, err := json.Marshal(rt)
	if err != nil {
		return err
	}

	// Keep for a short time to prevent replay attacks
	return r.redis.Set(ctx, tokenKey, data, 1*time.Hour).Err()
}

func (r *refreshTokenRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	tokens, err := r.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, token := range tokens {
		if err := r.Revoke(ctx, token.Token); err != nil {
			r.logger.Error(logging.Redis, logging.Delete, "Failed to revoke token", map[logging.ExtraKey]interface{}{
				"userID": userID.String(),
				"error":  err.Error(),
			})
		}
	}

	// Clear user's token set
	userTokensKey := fmt.Sprintf("%s%s", database.RedisKeyRefreshToken, userID.String())
	return r.redis.Del(ctx, userTokensKey).Err()
}

func (r *refreshTokenRepository) DeleteExpired(ctx context.Context) error {
	// Redis handles expiration automatically via TTL
	// This is a no-op but kept for interface compatibility
	return nil
}
