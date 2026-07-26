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
	db *gorm.DB,
	logger logging.Logger,
) *router.Handlers {
	return &router.Handlers{
		Auth:               handler.NewAuthHandler(services.Auth, services.OAuth, services.Token, services.ServiceAuth, services.KeyProvider, logger),
		User:               handler.NewUserHandler(services.User, services.OAuth, services.Tenant, logger),
		AdminUser:          handler.NewAdminUserHandler(services.User, logger),
		Role:               handler.NewRoleHandler(services.Role, logger),
		ServiceAuth:        handler.NewServiceAuthHandler(services.ServiceAuth, services.Token, logger),
		Health:             handler.NewHealthHandler(dbHealth, redisHealth),
		AdminServiceClient: handler.NewAdminServiceClientHandler(services.ServiceAuth, logger),
		AdminTenant:        handler.NewAdminTenantHandler(services.Tenant, logger),
		AdminOAuthProvider: handler.NewAdminOAuthProviderHandler(services.OAuthProvider, logger),
		AdminSettings:      handler.NewAdminSettingsHandler(services.Settings, services.SettingsRepo, logger),
		AdminDashboard:     handler.NewAdminDashboardHandler(db, logger),
		AdminSession:       handler.NewAdminSessionHandler(services.SessionRepo, services.RefreshTokenRepo, logger),
		AdminAudit:         handler.NewAdminAuditHandler(services.LoginLogRepo, db, logger),
		AdminTools:         handler.NewAdminToolsHandler(services.Token, services.KeyProvider, services.Auth, services.Role, logger),
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
