package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	customemiddlewares "github.com/minisource/auth/api/middlewares"
	"github.com/minisource/auth/api/routers"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/http/middlewares"
	"github.com/minisource/common_go/logging"
	// swaggerFiles "github.com/swaggo/files"
	// ginSwagger "github.com/swaggo/gin-swagger"
)

var logger = logging.NewLogger(&config.GetConfig().Logger)

func InitServer(cfg *config.Config) {
	gin.SetMode(cfg.Server.RunMode)
	r := gin.New()
	RegisterValidators()

	r.Use(middlewares.DefaultStructuredLogger(&cfg.Logger))
	r.Use(middlewares.Cors(cfg.Cors.AllowOrigins))
	r.Use(gin.Logger(), gin.CustomRecovery(middlewares.ErrorHandler) /*middlewares.TestMiddleware()*/, middlewares.LimitByRequest())

	RegisterRoutes(r, cfg)
	// RegisterSwagger(r, cfg)
	logger := logging.NewLogger(&cfg.Logger)
	logger.Info(logging.General, logging.Startup, "Started", nil)
	err := r.Run(fmt.Sprintf(":%s", cfg.Server.InternalPort))
	if err != nil {
		logger.Fatal(logging.General, logging.Startup, err.Error(), nil)
	}
}

func RegisterRoutes(r *gin.Engine, cfg *config.Config) {
	api := r.Group("/api")

	v1 := api.Group("/v1")
	{
		// Test
		health := v1.Group("/health", customemiddlewares.OAuthValidationMiddleware(cfg)) // TODO: remove middleware
		routers.Health(health)

		test_router := v1.Group("/test" /*middlewares.Authentication(cfg), middlewares.Authorization([]string{"admin"})*/)
		routers.TestRouter(test_router)

		// User
		users := v1.Group("/users")
		routers.User(users, cfg)

		// OAuth
		oauth := v1.Group("/oauth")
		routers.OAuthRouter(oauth, cfg)
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
