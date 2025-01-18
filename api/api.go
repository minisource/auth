package api

import (
	"fmt"

	"github.com/bytedance/sonic"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/minisource/auth/api/routers"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/http/middleware"
	"github.com/minisource/common_go/logging"
	// swaggerFiles "github.com/swaggo/files"
	// ginSwagger "github.com/swaggo/gin-swagger"
)

var logger = logging.NewLogger(&config.GetConfig().Logger)

func InitServer(cfg *config.Config) {
	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: middleware.CustomErrorHandler,
		AppName:     cfg.Server.Name,
		JSONEncoder: sonic.Marshal,
		JSONDecoder: sonic.Unmarshal,
	})

	// Middleware
	app.Use(middleware.DefaultStructuredLogger(&cfg.Logger)) // Custom structured logger
	app.Use(middleware.Cors(cfg.Cors.AllowOrigins))
	app.Use(recover.New())
	// app.Use(middleware.LimitByRequest()) // Custom rate limiter

	// Register routes
	RegisterRoutes(app, cfg)

	// Start the server
	logger := logging.NewLogger(&cfg.Logger)
	logger.Info(logging.General, logging.Startup, "Server started", nil)

	err := app.Listen(fmt.Sprintf(":%s", cfg.Server.InternalPort))
	if err != nil {
		logger.Fatal(logging.General, logging.Startup, err.Error(), nil)
	}
}

func RegisterRoutes(r fiber.Router, cfg *config.Config) {
	api := r.Group("/api")

	v1 := api.Group("/v1")
	{
		// Test
		health := v1.Group("/health")
		routers.Health(health)
		
		// OAuth
		oauth := v1.Group("/oauth")
		routers.OAuthRouter(oauth, cfg)

		// Authentication
		auth := v1.Group("/auth")
		routers.Authentication(auth, cfg)
	}
}

func RegisterValidators() {
	// val, ok := binding.Validator.Engine().(*validator.Validate)
	// if ok {
	// 	err := val.RegisterValidation("mobile", validation.IranianMobileNumberValidator, true)
	// 	if err != nil {
	// 		logger.Error(logging.Validation, logging.Startup, err.Error(), nil)
	// 	}
	// 	err = val.RegisterValidation("password", validation.PasswordValidator, true)
	// 	if err != nil {
	// 		logger.Error(logging.Validation, logging.Startup, err.Error(), nil)
	// 	}
	// }
}

// func RegisterSwagger(r *gin.Engine, cfg *config.Config) {
// 	docs.SwaggerInfo.Title = "golang web api"
// 	docs.SwaggerInfo.Description = "golang web api"
// 	docs.SwaggerInfo.Version = "1.0"
// 	docs.SwaggerInfo.BasePath = "/api"
// 	docs.SwaggerInfo.Host = fmt.Sprintf("localhost:%s", cfg.Server.ExternalPort)
// 	docs.SwaggerInfo.Schemes = []string{"http"}

// 	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
// }
