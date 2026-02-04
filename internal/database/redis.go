package database

import (
	"context"
	"fmt"
	"time"

	"github.com/minisource/auth/config"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
)

// InitRedis initializes the Redis connection
func InitRedis(cfg *config.RedisConfig, logger logging.Logger) (*redis.Client, error) {
	logger.Info(logging.Redis, logging.Startup, "Initializing Redis connection", map[logging.ExtraKey]interface{}{
		"host": cfg.Host,
		"port": cfg.Port,
		"db":   cfg.DB,
	})

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Host, cfg.Port),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		logger.Error(logging.Redis, logging.Startup, "Failed to connect to Redis", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.Info(logging.Redis, logging.Startup, "Redis connection established", nil)
	return client, nil
}

// RedisKeys defines standard key prefixes
const (
	RedisKeySession      = "session:"
	RedisKeyRefreshToken = "refresh:"
	RedisKeyOTP          = "otp:"
	RedisKeyUserSessions = "user_sessions:"
	RedisKeyBlacklist    = "blacklist:"
	RedisKeyRateLimit    = "rate_limit:"
)

// Helper functions for generating Redis keys
func OTPKey(target, otpType string) string {
	return fmt.Sprintf("%s%s:%s", RedisKeyOTP, otpType, target)
}

func RefreshTokenKey(token string) string {
	return fmt.Sprintf("%s%s", RedisKeyRefreshToken, token)
}

func SessionKey(sessionID string) string {
	return fmt.Sprintf("%s%s", RedisKeySession, sessionID)
}

func UserSessionsKey(userID string) string {
	return fmt.Sprintf("%s%s", RedisKeyUserSessions, userID)
}

func BlacklistKey(token string) string {
	return fmt.Sprintf("%s%s", RedisKeyBlacklist, token)
}
