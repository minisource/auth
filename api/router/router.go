package router

import (
	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"
	"github.com/minisource/auth/api/handler"
	"github.com/minisource/auth/api/middleware"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/audit"
	commonMiddleware "github.com/minisource/go-common/http/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gorm.io/gorm"
)

// Handlers holds all API handlers
type Handlers struct {
	Auth        *handler.AuthHandler
	User        *handler.UserHandler
	AdminUser   *handler.AdminUserHandler
	Role        *handler.RoleHandler
	ServiceAuth *handler.ServiceAuthHandler
	Health      *handler.HealthHandler
}

// Services holds services needed for middleware
type Services struct {
	Token       *service.TokenService
	ServiceAuth *service.ServiceAuthService
	DB          *gorm.DB // For tenant validation
	Audit       audit.Logger
}

// SetupRouter configures Fiber routes
func SetupRouter(cfg *config.Config, handlers *Handlers, services *Services) *fiber.App {
	app := fiber.New(fiber.Config{
		AppName:      "Auth Service",
		ErrorHandler: customErrorHandler,
	})

	// Global middleware
	app.Use(recover.New())

	// Security middleware
	app.Use(commonMiddleware.SecurityHeaders(commonMiddleware.DefaultSecurityHeadersConfig()))
	app.Use(commonMiddleware.RequestValidation(commonMiddleware.DefaultRequestValidationConfig()))

	app.Use(commonMiddleware.Prometheus())
	app.Use(commonMiddleware.Tracing(commonMiddleware.TracingConfig{
		ServiceName: "auth-service",
	}))
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} ${latency}\n",
	}))

	// CORS
	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.Cors.AllowedOrigins,
		AllowMethods:     "GET,POST,PUT,PATCH,DELETE,OPTIONS",
		AllowHeaders:     "Origin,Content-Type,Accept,Authorization,X-Tenant-ID",
		AllowCredentials: true,
	}))

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
			result := services.DB.Where("id = ? AND is_active = ?", tenantID, true).First(&tenant)
			return result.Error == nil
		},
	}))

	// Audit logging middleware
	if services.Audit != nil {
		app.Use(commonMiddleware.AuditLogger(commonMiddleware.DefaultAuditConfig(services.Audit)))
	}

	// Health endpoints
	app.Get("/health", handlers.Health.Health)
	app.Get("/ready", handlers.Health.Ready)

	// Prometheus metrics endpoint
	app.Get("/metrics", adaptor.HTTPHandler(promhttp.Handler()))

	// Swagger documentation
	app.Get("/swagger/*", swagger.HandlerDefault)

	// API v1
	v1 := app.Group("/api/v1")

	// Public auth routes
	auth := v1.Group("/auth")
	{
		auth.Post("/login", handlers.Auth.Login)
		auth.Post("/register", handlers.Auth.Register)
		auth.Post("/otp/send", handlers.Auth.SendOTP)
		auth.Post("/otp/verify", handlers.Auth.VerifyOTP)
		auth.Post("/refresh", handlers.Auth.RefreshToken)
		auth.Post("/forgot-password", handlers.Auth.ForgotPassword)
		auth.Post("/reset-password", handlers.Auth.ResetPassword)
		auth.Post("/verify-email", handlers.Auth.VerifyEmail)
		auth.Post("/resend-verification", handlers.Auth.ResendVerification)
		auth.Get("/google", handlers.Auth.GetGoogleAuthURL)
		auth.Get("/google/callback", handlers.Auth.GoogleCallback)
	}

	// Protected auth routes
	authProtected := v1.Group("/auth", middleware.AuthMiddleware(services.Token))
	{
		authProtected.Post("/logout", handlers.Auth.Logout)
	}

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
		users.Get("/me/linked-accounts", handlers.User.GetLinkedAccounts)
		users.Delete("/me/linked-accounts/google", handlers.User.UnlinkGoogleAccount)
	}

	// Admin routes
	admin := v1.Group("/admin",
		middleware.AuthMiddleware(services.Token),
		middleware.RequireRoles(models.RoleAdmin),
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
	admin.Post("/service-clients", handlers.ServiceAuth.CreateServiceClient)

	return app
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
