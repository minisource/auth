package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/minisource/auth/api/router"
	"github.com/minisource/auth/cmd/initializer"
	_ "github.com/minisource/auth/docs" // Import swagger docs
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
)

// @title Auth Service API
// @version 1.0
// @description Authentication and Authorization Service for Minisource
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@minisource.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host 127.0.0.1:9001
// @BasePath /api/v1
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Initialize configuration
	cfg := initializer.InitConfig()

	// Initialize logger
	logger := initializer.InitLogger(cfg)

	// Initialize metrics
	initializer.InitMetrics()

	// Initialize tracing (optional)
	tp := initializer.InitTracing(cfg, logger)
	if tp != nil {
		defer initializer.ShutdownTracing(tp, logger)
	}

	// Initialize translator
	initializer.InitTranslator(logger)

	// Initialize database connections
	db := initializer.InitDatabase(cfg, logger)
	rdb := initializer.InitRedis(cfg, logger)
	defer rdb.Close()

	// Initialize repositories
	repos := initializer.InitRepositories(db, rdb, logger)

	// Initialize services
	services := initializer.InitServices(cfg, repos, rdb, db, logger)

	// Close notifier client if it's a gRPC client
	if grpcClient, ok := services.Notifier.(*service.GRPCNotifierClient); ok {
		defer grpcClient.Close()
	}

	// Initialize health checkers
	dbHealth, redisHealth := initializer.InitHealthCheckers(db, rdb)

	// Initialize handlers
	handlers := initializer.InitHandlers(services, dbHealth, redisHealth, logger)

	// Initialize router services
	routerServices := initializer.InitRouterServices(services, db)

	// Setup router
	app := router.SetupRouter(cfg, handlers, routerServices)

	// Start server
	go func() {
		addr := fmt.Sprintf(":%s", cfg.Server.Port)
		logger.Info(logging.General, logging.Startup, "Server starting", map[logging.ExtraKey]interface{}{
			"address": addr,
		})
		if err := app.Listen(addr); err != nil {
			logger.Fatal(logging.General, logging.Startup, "Failed to start server", map[logging.ExtraKey]interface{}{
				"error": err.Error(),
			})
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info(logging.General, logging.Startup, "Shutting down server...", nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := app.ShutdownWithContext(ctx); err != nil {
		logger.Error(logging.General, logging.Startup, "Server forced to shutdown", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}

	logger.Info(logging.General, logging.Startup, "Server exited properly", nil)
}
