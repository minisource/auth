package router

import (
	"sync"
	"time"

	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/minisource/auth/api/handler"
	"github.com/minisource/auth/api/middleware"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/audit"
	commonMiddleware "github.com/minisource/go-common/http/middleware"
	"github.com/minisource/go-common/i18n"
	"github.com/minisource/go-common/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gorm.io/gorm"
)

// Handlers holds all API handlers
type Handlers struct {
	Auth               *handler.AuthHandler
	User               *handler.UserHandler
	AdminUser          *handler.AdminUserHandler
	Role               *handler.RoleHandler
	ServiceAuth        *handler.ServiceAuthHandler
	Health             *handler.HealthHandler
	AdminServiceClient *handler.AdminServiceClientHandler
	AdminTenant        *handler.AdminTenantHandler
	AdminOAuthProvider *handler.AdminOAuthProviderHandler
	AdminSettings      *handler.AdminSettingsHandler
	AdminDashboard     *handler.AdminDashboardHandler
	AdminSession       *handler.AdminSessionHandler
	AdminAudit         *handler.AdminAuditHandler
	AdminTools         *handler.AdminToolsHandler
	AdminRetention     *handler.AdminRetentionHandler
	WebAuthn           *handler.WebAuthnHandler
	Realtime           *handler.RealtimeHandler
}

// Services holds services needed for middleware
type Services struct {
	Token       *service.TokenService
	ServiceAuth *service.ServiceAuthService
	DB          *gorm.DB // For tenant validation
	Audit       audit.Logger
}

// SetupRouter configures Fiber routes
func SetupRouter(cfg *config.Config, handlers *Handlers, services *Services, logger logging.Logger) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      "Auth Service",
		ErrorHandler: customErrorHandler,
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(i18n.Middleware())

	// Request ID — runs before tracing so spans carry request.id
	app.Use(commonMiddleware.RequestID())

	// CORS — Allow all origins, headers, methods, and credentials
	app.Use(cors.New(cors.Config{
		AllowOriginsFunc: func(origin string) bool {
			return true
		},
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "*",
		ExposeHeaders:    "*",
		AllowCredentials: true,
	}))

	// Security middleware
	app.Use(commonMiddleware.SecurityHeaders(commonMiddleware.DefaultSecurityHeadersConfig()))
	app.Use(commonMiddleware.RequestValidation(commonMiddleware.DefaultRequestValidationConfig()))

	app.Use(commonMiddleware.Prometheus())
	app.Use(commonMiddleware.Tracing(commonMiddleware.TracingConfig{
		ServiceName: "auth-service",
	}))

	// Structured access log — canonical http_request_completed event
	app.Use(commonMiddleware.AccessLog(commonMiddleware.LoadAccessLogConfigFromEnv("auth-service", logger)))

	// Tenant middleware - extract and validate tenant context
	app.Use(commonMiddleware.TenantMiddleware(commonMiddleware.TenantConfig{
		Enabled:            true,
		HeaderName:         "X-Tenant-ID",
		AllowMissingTenant: true, // Allow missing for public routes
		ContextKey:         "tenantId",
		SkipPaths:          []string{"/health", "/ready", "/swagger", "/metrics"},
		TenantValidator: func(tenantID string) bool {
			// Validate tenant exists and is active
			if services.DB == nil {
				return true // Skip validation if DB not available
			}
			var tenant models.Tenant
			// Dev mode: skip if no tenants in DB (allows bootstrapping)
			var count int64
			services.DB.Model(&models.Tenant{}).Count(&count)
			if count == 0 {
				return true
			}
			result := services.DB.Where("(id = ? OR slug = ?) AND status = 'active'", tenantID, tenantID).First(&tenant)
			return result.Error == nil
		},
	}))

	// Audit logging middleware
	if services.Audit != nil {
		app.Use(commonMiddleware.AuditLogger(commonMiddleware.DefaultAuditConfig(services.Audit)))
	}

	// Rate limiter for auth endpoints
	rateLimiter := newRateLimiter()

	// Health endpoints
	app.Get("/health", handlers.Health.Health)
	app.Get("/ready", handlers.Health.Ready)

	// Prometheus metrics endpoint.
	// ContinueOnError: if an external scraper/probe ever causes a duplicate
	// label set across collector generations, skip the colliding series instead
	// of failing the whole scrape with HTTP 500.
	app.Get("/metrics", adaptor.HTTPHandler(promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError},
	)))

	// Swagger documentation
	app.Get("/swagger/*", swagger.HandlerDefault)

	// JWKS endpoints (public, no auth)
	app.Get("/.well-known/jwks.json", handlers.Auth.JWKS)

	// Register /api/v1 routes (backward compatible)
	registerAPIRoutes("/api/v1", app, handlers, services, rateLimiter, cfg)

	// Register /v1 routes (canonical)
	registerAPIRoutes("/v1", app, handlers, services, rateLimiter, cfg)

	return app
}

// registerAPIRoutes registers all API routes under the given prefix
func registerAPIRoutes(prefix string, app *fiber.App, handlers *Handlers, services *Services, rl *rateLimiter, cfg *config.Config) {
	v1 := app.Group(prefix)

	// JWKS under prefix as well
	v1.Get("/.well-known/jwks.json", handlers.Auth.JWKS)

	// Public auth routes (with rate limiting)
	auth := v1.Group("/auth")
	{
		auth.Post("/login", rl.limit(cfg.RateLimit.LoginPerMinute), handlers.Auth.Login)
		auth.Post("/register", rl.limit(cfg.RateLimit.RegisterPerMinute), handlers.Auth.Register)
		auth.Post("/otp/send", rl.limit(cfg.RateLimit.OTPPerMinute), handlers.Auth.SendOTP)
		auth.Post("/otp/verify", rl.limit(cfg.RateLimit.OTPPerMinute), handlers.Auth.VerifyOTP)
		auth.Post("/refresh", handlers.Auth.RefreshToken)
		auth.Post("/forgot-password", rl.limit(cfg.RateLimit.PasswordResetPerHour), handlers.Auth.ForgotPassword)
		auth.Post("/reset-password", rl.limit(cfg.RateLimit.PasswordResetPerHour), handlers.Auth.ResetPassword)
		auth.Post("/verify-email", handlers.Auth.VerifyEmail)
		auth.Post("/verify-2fa", rl.limit(cfg.RateLimit.OTPPerMinute), handlers.Auth.VerifyTwoFactor)
		auth.Post("/resend-verification", rl.limit(cfg.RateLimit.OTPPerMinute), handlers.Auth.ResendVerification)
		auth.Get("/google", handlers.Auth.GetGoogleAuthURL)
		auth.Get("/google/callback", handlers.Auth.GoogleCallback)
		auth.Post("/google/mobile", handlers.Auth.GoogleMobileLogin)
		auth.Get("/seed-status", handlers.Auth.GetSeedStatus)
		auth.Post("/webauthn/begin", rl.limit(cfg.RateLimit.OTPPerMinute), handlers.WebAuthn.BeginLogin)
		auth.Post("/webauthn/finish", rl.limit(cfg.RateLimit.OTPPerMinute), handlers.WebAuthn.FinishLogin)

		// Protected auth routes
		authProtected := v1.Group("/auth", middleware.AuthMiddleware(services.Token))
		{
			authProtected.Post("/logout", handlers.Auth.Logout)
		}

		// Userinfo (protected)
		auth.Get("/userinfo", middleware.AuthMiddleware(services.Token), handlers.Auth.Userinfo)

		// Introspect (public in dev, optionally service-auth in production)
		auth.Post("/introspect", handlers.Auth.Introspect)
	}

	// Token validation for microservices (user JWT or service JWT in Authorization header)
	v1.Get("/tokens/validate", handlers.ServiceAuth.ValidateBearerToken)

	// Service authentication (for other services)
	serviceAuth := v1.Group("/service")
	{
		// Public endpoint - services authenticate here to get a token
		serviceAuth.Post("/auth", handlers.ServiceAuth.Authenticate)
		// Protected endpoint - requires a valid service token to validate
		serviceAuth.Get("/validate", middleware.ServiceAuthMiddleware(services.ServiceAuth), handlers.ServiceAuth.ValidateToken)
	}

	// User routes (authenticated)
	users := v1.Group("/users", middleware.AuthMiddleware(services.Token))
	{
		users.Get("/me", handlers.User.GetProfile)
		users.Put("/me", handlers.User.UpdateProfile)
		users.Put("/me/password", handlers.User.ChangePassword)
		users.Post("/me/password/set", handlers.User.SetPassword)
		users.Get("/me/sessions", handlers.User.GetSessions)
		users.Delete("/me/sessions/:id", handlers.User.RevokeSession)
		users.Get("/me/2fa/status", handlers.User.GetTwoFactorStatus)
		users.Post("/me/2fa/setup", handlers.User.SetupTwoFactor)
		users.Post("/me/2fa/enable", handlers.User.EnableTwoFactor)
		users.Post("/me/2fa/disable", handlers.User.DisableTwoFactor)
		users.Get("/me/security-events", handlers.User.GetSecurityEvents)
		users.Get("/me/passkeys", handlers.WebAuthn.ListPasskeys)
		users.Post("/me/passkeys/register/begin", handlers.WebAuthn.BeginRegistration)
		users.Post("/me/passkeys/register/finish", handlers.WebAuthn.FinishRegistration)
		users.Delete("/me/passkeys/:id", handlers.WebAuthn.DeletePasskey)
		users.Get("/me/tenants", handlers.User.GetMyTenants)
		users.Get("/me/linked-accounts", handlers.User.GetLinkedAccounts)
		users.Delete("/me/linked-accounts/google", handlers.User.UnlinkGoogleAccount)
	}

	// Account routes — authenticated phone/identity management
	account := v1.Group("/account", middleware.AuthMiddleware(services.Token))
	{
	account.Post("/phone/start", handlers.Auth.PhoneStart)
	account.Post("/phone/verify", handlers.Auth.PhoneVerify)
	account.Post("/email/start", handlers.Auth.EmailStart)
	account.Post("/email/verify", handlers.Auth.EmailVerify)
	}

	// Admin routes — system_admin and super_admin also have access
	admin := v1.Group("/admin",
		middleware.AuthMiddleware(services.Token),
		middleware.RequireRoles(models.RoleAdmin, models.RoleSuperAdmin),
	)

	// Admin user management
	adminUsers := admin.Group("/users")
	{
		adminUsers.Get("/", handlers.AdminUser.ListUsers)
		adminUsers.Get("/:id", handlers.AdminUser.GetUser)
		adminUsers.Post("/", handlers.AdminUser.CreateUser)
		adminUsers.Put("/:id", handlers.AdminUser.UpdateUser)
		adminUsers.Delete("/:id", handlers.AdminUser.DeleteUser)
		adminUsers.Patch("/:id/status/:status", handlers.AdminUser.ToggleUserStatus)
		adminUsers.Post("/:id/unlock", handlers.AdminUser.UnlockUser)
	}

	// Admin role management
	adminRoles := admin.Group("/roles")
	{
		adminRoles.Get("/", handlers.Role.ListRoles)
		adminRoles.Get("/:id", handlers.Role.GetRole)
		adminRoles.Post("/", handlers.Role.CreateRole)
		adminRoles.Put("/:id", handlers.Role.UpdateRole)
		adminRoles.Delete("/:id", handlers.Role.DeleteRole)
		adminRoles.Post("/:roleId/permissions/:permissionId", handlers.Role.AssignPermissionToRole)
		adminRoles.Delete("/:roleId/permissions/:permissionId", handlers.Role.RemovePermissionFromRole)
	}

	// Admin permission management
	adminPermissions := admin.Group("/permissions")
	{
		adminPermissions.Get("/", handlers.Role.ListPermissions)
		adminPermissions.Get("/:id", handlers.Role.GetPermission)
		adminPermissions.Post("/", handlers.Role.CreatePermission)
		adminPermissions.Put("/:id", handlers.Role.UpdatePermission)
		adminPermissions.Delete("/:id", handlers.Role.DeletePermission)
	}

	// Admin service client management
	adminServiceClients := admin.Group("/service-clients")
	{
		adminServiceClients.Post("/", handlers.ServiceAuth.CreateServiceClient)
		adminServiceClients.Get("/", handlers.AdminServiceClient.ListServiceClients)
		adminServiceClients.Get("/:id", handlers.AdminServiceClient.GetServiceClient)
		adminServiceClients.Put("/:id", handlers.AdminServiceClient.UpdateServiceClient)
		adminServiceClients.Delete("/:id", handlers.AdminServiceClient.DeleteServiceClient)
		adminServiceClients.Patch("/:id/status/:status", handlers.AdminServiceClient.ToggleServiceClientStatus)
		adminServiceClients.Post("/:id/rotate-secret", handlers.AdminServiceClient.RotateServiceClientSecret)
	}

	// Admin tenant management
	adminTenants := admin.Group("/tenants")
	{
		adminTenants.Get("/", handlers.AdminTenant.ListTenants)
		adminTenants.Get("/:id", handlers.AdminTenant.GetTenant)
		adminTenants.Post("/", handlers.AdminTenant.CreateTenant)
		adminTenants.Put("/:id", handlers.AdminTenant.UpdateTenant)
		adminTenants.Delete("/:id", handlers.AdminTenant.DeleteTenant)
		adminTenants.Patch("/:id/status/:status", handlers.AdminTenant.ToggleTenantStatus)

		// Tenant members
		adminTenants.Get("/:id/members", handlers.AdminTenant.ListTenantMembers)
		adminTenants.Post("/:id/members", handlers.AdminTenant.AddTenantMember)
		adminTenants.Patch("/:id/members/:userId", handlers.AdminTenant.UpdateTenantMember)
		adminTenants.Delete("/:id/members/:userId", handlers.AdminTenant.RemoveTenantMember)

		// Tenant invitations
		adminTenants.Get("/:id/invitations", handlers.AdminTenant.ListTenantInvitations)
		adminTenants.Post("/:id/invitations", handlers.AdminTenant.InviteTenantMember)
		adminTenants.Delete("/:id/invitations/:invitationId", handlers.AdminTenant.RevokeTenantInvitation)
	}

	// Admin OAuth provider management
	adminOAuthProviders := admin.Group("/oauth-providers")
	{
		adminOAuthProviders.Get("/", handlers.AdminOAuthProvider.ListOAuthProviders)
		adminOAuthProviders.Get("/:id", handlers.AdminOAuthProvider.GetOAuthProvider)
		adminOAuthProviders.Post("/", handlers.AdminOAuthProvider.CreateOAuthProvider)
		adminOAuthProviders.Put("/:id", handlers.AdminOAuthProvider.UpdateOAuthProvider)
		adminOAuthProviders.Delete("/:id", handlers.AdminOAuthProvider.DeleteOAuthProvider)
		adminOAuthProviders.Patch("/:id/toggle", handlers.AdminOAuthProvider.ToggleOAuthProvider)
	}

	// Admin settings
	adminSettings := admin.Group("/settings")
	{
		adminSettings.Get("/", handlers.AdminSettings.GetSettings)
		adminSettings.Get("/:category", handlers.AdminSettings.GetSettingsByCategory)
		adminSettings.Patch("/", handlers.AdminSettings.UpdateSettings)
		adminSettings.Patch("/:category", handlers.AdminSettings.UpdateSettingsByCategory)
	}

	// Admin dashboard
	adminDashboard := admin.Group("/dashboard")
	{
		adminDashboard.Get("/overview", handlers.AdminDashboard.GetDashboardOverview)
		adminDashboard.Get("/recent-activity", handlers.AdminDashboard.GetRecentActivity)
	}

	// Admin sessions
	adminSessions := admin.Group("/sessions")
	{
		adminSessions.Get("/", handlers.AdminSession.ListAllSessions)
		adminSessions.Delete("/:id", handlers.AdminSession.RevokeSession)
	}
	// Admin user sessions (revoke all)
	adminUsersSessions := admin.Group("/users")
	{
		adminUsersSessions.Delete("/:userId/sessions", handlers.AdminSession.RevokeUserAllSessions)
	}

	// Admin audit logs
	adminAudit := admin.Group("")
	{
		adminAudit.Get("/login-logs", handlers.AdminAudit.ListLoginLogs)
		adminAudit.Get("/audit-logs", handlers.AdminAudit.ListAuditLogs)
	}

	// Admin tools
	adminTools := admin.Group("/tools")
	{
		adminTools.Post("/introspect-token", handlers.AdminTools.IntrospectToken)
		adminTools.Post("/check-permission", handlers.AdminTools.CheckPermission)
		adminTools.Get("/jwks-status", handlers.AdminTools.JWKSStatus)
		adminTools.Get("/health", handlers.AdminTools.ToolsHealth)
		adminTools.Get("/notifier-health", handlers.AdminTools.NotifierHealth)
	}

	// Admin log retention
	adminRetention := admin.Group("/log-retention")
	{
		adminRetention.Get("/categories", handlers.AdminRetention.ListCategories)
		adminRetention.Get("/policies", handlers.AdminRetention.ListPolicies)
		adminRetention.Get("/policies/:id", handlers.AdminRetention.GetPolicy)
		adminRetention.Put("/policies/:id", handlers.AdminRetention.UpsertPolicy)
		adminRetention.Post("/policies/:id/enable", handlers.AdminRetention.EnablePolicy)
		adminRetention.Post("/policies/:id/disable", handlers.AdminRetention.DisablePolicy)
		adminRetention.Post("/policies/:id/preview", handlers.AdminRetention.PreviewCleanup)
		adminRetention.Post("/policies/:id/run", handlers.AdminRetention.RunCleanup)
		adminRetention.Get("/runs", handlers.AdminRetention.ListRuns)
		adminRetention.Get("/runs/:id", handlers.AdminRetention.GetRun)
	}

	// Admin realtime events (SSE). The admin group middleware already enforces
	// admin role; static /events route registered after the param routes.
	admin.Get("/events", handlers.Realtime.HandleSSE)
}

// rateLimiter provides per-route IP-based rate limiting
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count    int
	resetAt  time.Time
	limit    int
	duration time.Duration
}

func newRateLimiter() *rateLimiter {
	rl := &rateLimiter{
		buckets: make(map[string]*bucket),
	}
	go rl.cleanup()
	return rl
}

func (rl *rateLimiter) limit(maxPerDuration int) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Rate limiting controlled by env vars — set *_RATE_LIMIT_*=0 to disable
		if maxPerDuration <= 0 {
			return c.Next()
		}

		ip := c.IP()
		key := ip + ":" + c.Path()

		rl.mu.Lock()
		b, exists := rl.buckets[key]
		now := time.Now()

		if !exists || now.After(b.resetAt) {
			rl.buckets[key] = &bucket{
				count:    1,
				resetAt:  now.Add(time.Minute),
				limit:    maxPerDuration,
				duration: time.Minute,
			}
			rl.mu.Unlock()
			return c.Next()
		}

		b.count++
		if b.count > b.limit {
			rl.mu.Unlock()
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"success": false,
				"error": fiber.Map{
					"code":    "RATE_LIMITED",
					"message": "Too many attempts. Please try again later.",
				},
			})
		}
		rl.mu.Unlock()
		return c.Next()
	}
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, b := range rl.buckets {
			if now.After(b.resetAt) {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error": err.Error(),
	})
}
