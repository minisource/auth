package initializer

import (
	"context"
	"fmt"
	"time"

	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/events"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/auth/internal/retention"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/audit"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-sdk/auth"
	"github.com/minisource/go-sdk/notifier"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Services holds all service instances
type Services struct {
	Token         *service.TokenService
	KeyProvider   *service.KeyProvider
	Password      *service.PasswordService
	Settings      *service.SettingsService
	Notifier      service.NotifierClient
	OTP           *service.OTPService
	ServiceAuth   *service.ServiceAuthService
	Auth          *service.AuthService
	OAuth         *service.OAuthService
	OAuthProvider service.OAuthProviderService
	User          *service.UserService
	Role          *service.RoleService
	Tenant        service.TenantService
	Audit         audit.Logger
	WebAuthn      *service.WebAuthnService

	// Repositories needed by admin handlers
	SettingsRepo      repository.SettingRepository
	SessionRepo       repository.SessionRepository
	RefreshTokenRepo  repository.RefreshTokenRepository
	LoginLogRepo      repository.LoginLogRepository
	ServiceClientRepo repository.ServiceClientRepository

	// Retention
	RetentionPolicyRepo retention.PolicyRepository
	RetentionRunRepo    retention.RunRepository
	RetentionScheduler  *retention.Scheduler

	// Realtime
	Events *events.Bus
}

// InitServices creates all service instances
func InitServices(cfg *config.Config, repos *Repositories, rdb *redis.Client, db *gorm.DB, logger logging.Logger) *Services {
	// Initialize key provider (RS256 or HS256)
	keyProvider, err := service.NewKeyProvider(&cfg.JWT)
	if err != nil {
		logger.Fatal(logging.General, logging.Startup, "Failed to initialize key provider", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}

	// Initialize basic services
	tokenService := service.NewTokenService(&cfg.JWT, keyProvider)
	passwordService := service.NewPasswordService(&cfg.Password)
	settingsService := service.NewSettingsService(cfg, repos.Setting, rdb, logger)

	// Initialize the realtime admin event bus (SSE /v1/admin/events). The bus
	// relays events across instances through Redis Pub/Sub so every admin
	// dashboard sees events no matter which instance produced them.
	logger.Info(logging.General, logging.Startup, "Initializing realtime event bus", nil)
	eventBus := events.NewRelayedBus(logger, rdb)

	// Initialize audit logger — wrapped so every persisted audit entry also
	// pushes a sanitized audit.entry_created event to admin dashboards.
	auditLogger := events.NewPublishingAuditLogger(audit.NewService(db), eventBus)

	// Initialize notifier client
	notifierClient := initNotifierClient(cfg, logger)

	// Initialize OTP service
	otpService := service.NewOTPService(&cfg.OTP, repos.OTP, logger, notifierClient, settingsService)

	// Initialize service auth
	serviceAuthService := service.NewServiceAuthService(&cfg.JWT, keyProvider, repos.ServiceClient, passwordService, logger)

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
		repos.RefreshToken,
		repos.LoginLog,
		passwordService,
		logger,
	)

	// Initialize role service
	roleService := service.NewRoleService(repos.Role, repos.Permission)

	// Initialize tenant service
	tenantService := service.NewTenantService(repos.Tenant, repos.User, repos.Role, logger)

	// Initialize OAuth provider service
	oauthProviderService := service.NewOAuthProviderService(repos.OAuthProvider, logger)

	// Initialize WebAuthn (passkey) service
	webAuthnService, err := service.NewWebAuthnService(cfg, repos.Passkey, repos.User, authService, rdb, logger)
	if err != nil {
		logger.Fatal(logging.General, logging.Startup, "Failed to initialize WebAuthn service", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}

	// Wire the realtime event bus into the auth service (login/logout events).
	authService.SetEventBus(eventBus)

	return &Services{
		Token:         tokenService,
		KeyProvider:   keyProvider,
		Password:      passwordService,
		Settings:      settingsService,
		Notifier:      notifierClient,
		OTP:           otpService,
		ServiceAuth:   serviceAuthService,
		Auth:          authService,
		OAuth:         oauthService,
		OAuthProvider: oauthProviderService,
		User:          userService,
		Role:          roleService,
		Tenant:        tenantService,
		Audit:         auditLogger,
		WebAuthn:      webAuthnService,

		// Repositories for admin handlers
		SettingsRepo:      repos.Setting,
		SessionRepo:       repos.Session,
		RefreshTokenRepo:  repos.RefreshToken,
		LoginLogRepo:      repos.LoginLog,
		ServiceClientRepo: repos.ServiceClient,

		// Retention
		RetentionPolicyRepo: retention.NewPolicyRepository(db, logger),
		RetentionRunRepo:    retention.NewRunRepository(db, logger),
		RetentionScheduler: initRetention(db, logger),

		// Realtime
		Events: eventBus,
	}
}

// initRetention creates the retention scheduler and its dependencies.
func initRetention(db *gorm.DB, logger logging.Logger) *retention.Scheduler {
	policyRepo := retention.NewPolicyRepository(db, logger)
	runRepo := retention.NewRunRepository(db, logger)
	runner := retention.NewAuthRunner(db, logger)
	lock := retention.NewPGLock(db)

	scheduler := retention.NewScheduler(policyRepo, runRepo, runner, lock, logger)
	scheduler.Start()
	return scheduler
}

// initNotifierClient creates notifier client with fallback to noop client using go-sdk
func initNotifierClient(cfg *config.Config, logger logging.Logger) service.NotifierClient {
	if !cfg.Notifier.Enabled {
		logger.Info(logging.General, logging.Startup, "Notifier service disabled in config", nil)
		return service.NewNoopNotifierClient(logger)
	}

	var authClient *auth.Client
	if cfg.Notifier.ClientID != "" && cfg.Notifier.ClientSecret != "" {
		authBaseURL := cfg.Notifier.AuthURL
		if authBaseURL == "" {
			authBaseURL = fmt.Sprintf("http://localhost:%s", cfg.Server.Port)
		}
		authClient = auth.NewClient(auth.ClientConfig{
			BaseURL:      authBaseURL,
			ClientID:     cfg.Notifier.ClientID,
			ClientSecret: cfg.Notifier.ClientSecret,
			Timeout:      10 * time.Second,
			AutoRefresh:  true,
			Logger:       logger,
		})
	}

	sdkClient, err := notifier.NewClient(context.Background(), notifier.Config{
		Address:    cfg.Notifier.GRPCAddress,
		Timeout:    30 * time.Second,
		AuthClient: authClient,
		Logger:     logger,
	})
	if err != nil {
		logger.Warn(logging.General, logging.Startup, "Failed to connect to notifier service, using noop client", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return service.NewNoopNotifierClient(logger)
	}

	return sdkClient
}
