package initializer

import (
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/database"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// InitDatabase initializes PostgreSQL database connection
func InitDatabase(cfg *config.Config, logger logging.Logger) *gorm.DB {
	db, err := database.InitDatabase(&cfg.Postgres, &cfg.Database, logger)
	if err != nil {
		logger.Fatal(logging.Postgres, logging.Startup, "Failed to connect to database", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}
	logger.Info(logging.Postgres, logging.Startup, "Database connected", nil)
	return db
}

// InitRedis initializes Redis connection
func InitRedis(cfg *config.Config, logger logging.Logger) *redis.Client {
	rdb, err := database.InitRedis(&cfg.Redis, logger)
	if err != nil {
		logger.Fatal(logging.Redis, logging.Startup, "Failed to connect to Redis", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}
	logger.Info(logging.Redis, logging.Startup, "Redis connected", nil)
	return rdb
}

// InitHealthCheckers creates database and redis health checkers
func InitHealthCheckers(db *gorm.DB, rdb *redis.Client) (*database.DBHealthChecker, *database.RedisHealthChecker) {
	dbHealth := database.NewDBHealthChecker(db)
	redisHealth := database.NewRedisHealthChecker(rdb)
	return dbHealth, redisHealth
}
