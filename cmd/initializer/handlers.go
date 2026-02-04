package initializer

import (
	"github.com/minisource/auth/api/handler"
	"github.com/minisource/auth/api/router"
	"github.com/minisource/auth/internal/database"
	"github.com/minisource/go-common/logging"
	"gorm.io/gorm"
)

// InitHandlers creates all HTTP handlers
func InitHandlers(
	services *Services,
	dbHealth *database.DBHealthChecker,
	redisHealth *database.RedisHealthChecker,
	logger logging.Logger,
) *router.Handlers {
	return &router.Handlers{
		Auth:        handler.NewAuthHandler(services.Auth, services.OAuth, logger),
		User:        handler.NewUserHandler(services.User, services.OAuth, logger),
		AdminUser:   handler.NewAdminUserHandler(services.User, logger),
		Role:        handler.NewRoleHandler(services.Role, logger),
		ServiceAuth: handler.NewServiceAuthHandler(services.ServiceAuth, logger),
		Health:      handler.NewHealthHandler(dbHealth, redisHealth),
	}
}

// InitRouterServices creates services struct for router
func InitRouterServices(services *Services, db *gorm.DB) *router.Services {
	return &router.Services{
		Token:       services.Token,
		ServiceAuth: services.ServiceAuth,
		DB:          db,
		Audit:       services.Audit,
	}
}
