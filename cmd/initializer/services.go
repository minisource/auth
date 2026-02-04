package initializer

import (
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/audit"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Services holds all service instances
type Services struct {
	Token       *service.TokenService
	Password    *service.PasswordService
	Settings    *service.SettingsService
	Notifier    service.NotifierClient
	OTP         *service.OTPService
	ServiceAuth *service.ServiceAuthService
	Auth        *service.AuthService
	OAuth       *service.OAuthService
	User        *service.UserService
	Role        *service.RoleService
	Audit       audit.Logger
}

// InitServices creates all service instances
func InitServices(cfg *config.Config, repos *Repositories, rdb *redis.Client, db *gorm.DB, logger logging.Logger) *Services {
	// Initialize basic services
	tokenService := service.NewTokenService(&cfg.JWT)
	passwordService := service.NewPasswordService(&cfg.Password)
	settingsService := service.NewSettingsService(cfg, repos.Setting, rdb, logger)

	// Initialize audit logger
	auditLogger := audit.NewService(db)

	// Initialize notifier client
	notifierClient := initNotifierClient(cfg, logger)

	// Initialize OTP service
	otpService := service.NewOTPService(&cfg.OTP, repos.OTP, logger, notifierClient, settingsService)

	// Initialize service auth
	serviceAuthService := service.NewServiceAuthService(&cfg.JWT, repos.ServiceClient, passwordService, logger)

	// Initialize auth service
	authService := service.NewAuthService(
		cfg,
		repos.User,
		repos.Session,
		repos.RefreshToken,
		repos.Role,
		repos.LoginLog,
		tokenService,
		passwordService,
		otpService,
		settingsService,
		logger,
	)

	// Initialize OAuth service
	oauthService := service.NewOAuthService(
		cfg,
		repos.User,
		repos.OAuth,
		repos.Role,
		repos.Session,
		repos.RefreshToken,
		repos.LoginLog,
		tokenService,
		settingsService,
		logger,
	)

	// Initialize user service
	userService := service.NewUserService(
		cfg,
		repos.User,
		repos.Role,
		repos.Session,
		passwordService,
		logger,
	)

	// Initialize role service
	roleService := service.NewRoleService(repos.Role, repos.Permission)

	return &Services{
		Token:       tokenService,
		Password:    passwordService,
		Settings:    settingsService,
		Notifier:    notifierClient,
		OTP:         otpService,
		ServiceAuth: serviceAuthService,
		Auth:        authService,
		OAuth:       oauthService,
		User:        userService,
		Role:        roleService,
		Audit:       auditLogger,
	}
}

// initNotifierClient creates notifier client with fallback to noop client
func initNotifierClient(cfg *config.Config, logger logging.Logger) service.NotifierClient {
	if !cfg.Notifier.Enabled {
		logger.Info(logging.General, logging.Startup, "Notifier service disabled in config", nil)
		return service.NewNoopNotifierClient(logger)
	}

	grpcNotifier, err := service.NewGRPCNotifierClient(&cfg.Notifier, cfg, logger)
	if err != nil {
		logger.Warn(logging.General, logging.Startup, "Failed to connect to notifier service, using noop client", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return service.NewNoopNotifierClient(logger)
	}

	if grpcNotifier != nil {
		return grpcNotifier
	}

	return service.NewNoopNotifierClient(logger)
}
