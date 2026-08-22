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
	adminUser := handler.NewAdminUserHandler(services.User, logger)
	role := handler.NewRoleHandler(services.Role, logger)
	adminTenant := handler.NewAdminTenantHandler(services.Tenant, logger)
	adminSettings := handler.NewAdminSettingsHandler(services.Settings, services.SettingsRepo, logger)
	adminSession := handler.NewAdminSessionHandler(services.SessionRepo, services.RefreshTokenRepo, logger)

	// Wire the realtime event bus into admin mutation handlers so admin
	// actions push SSE events to connected dashboards.
	adminUser.SetEventBus(services.Events)
	role.SetEventBus(services.Events)
	adminTenant.SetEventBus(services.Events)
	adminSettings.SetEventBus(services.Events)
	adminSession.SetEventBus(services.Events)

	return &router.Handlers{
		Auth:               handler.NewAuthHandler(services.Auth, services.OAuth, services.Token, services.ServiceAuth, services.KeyProvider, logger),
		User:               handler.NewUserHandler(services.User, services.OAuth, services.Tenant, logger),
		AdminUser:          adminUser,
		Role:               role,
		ServiceAuth:        handler.NewServiceAuthHandler(services.ServiceAuth, services.Token, logger),
		Health:             handler.NewHealthHandler(dbHealth, redisHealth),
		AdminServiceClient: handler.NewAdminServiceClientHandler(services.ServiceAuth, logger),
		AdminTenant:        adminTenant,
		AdminOAuthProvider: handler.NewAdminOAuthProviderHandler(services.OAuthProvider, logger),
		AdminSettings:      adminSettings,
		AdminDashboard:     handler.NewAdminDashboardHandler(db, logger),
		AdminSession:       adminSession,
		AdminAudit:         handler.NewAdminAuditHandler(services.LoginLogRepo, db, logger),
		AdminTools:         handler.NewAdminToolsHandler(services.Token, services.KeyProvider, services.Auth, services.Role, logger),
		AdminRetention:     handler.NewAdminRetentionHandler(services.RetentionPolicyRepo, services.RetentionRunRepo, services.RetentionScheduler, logger),
		WebAuthn:           handler.NewWebAuthnHandler(services.WebAuthn, logger),
		Realtime:           handler.NewRealtimeHandler(services.Events, logger),
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
