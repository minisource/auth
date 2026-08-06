package database

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// DBHealthChecker wraps a GORM DB to implement health checking
type DBHealthChecker struct {
	db *gorm.DB
}

// NewDBHealthChecker creates a new health checker for GORM DB
func NewDBHealthChecker(db *gorm.DB) *DBHealthChecker {
	return &DBHealthChecker{db: db}
}

// Ping checks database connectivity
func (h *DBHealthChecker) Ping() error {
	sqlDB, err := h.db.DB()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return sqlDB.PingContext(ctx)
}

// RedisHealthChecker wraps a Redis client to implement health checking
type RedisHealthChecker struct {
	client *redis.Client
}

// NewRedisHealthChecker creates a new health checker for Redis
func NewRedisHealthChecker(client *redis.Client) *RedisHealthChecker {
	return &RedisHealthChecker{client: client}
}

// Ping checks Redis connectivity
func (h *RedisHealthChecker) Ping() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.client.Ping(ctx).Err()
}
