package initializer

import (
	"context"
	"log"

	"github.com/minisource/auth/config"
	"github.com/minisource/go-common/i18n"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/metrics"
	commonTracing "github.com/minisource/go-common/tracing"
)

// InitConfig loads configuration from environment
func InitConfig() *config.Config {
	cfg := config.GetConfig()

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Config validation failed: %v", err)
	}

	logConfigSummary(cfg)
	return cfg
}

func logConfigSummary(cfg *config.Config) {
	log.Printf("Auth config validation passed")
	log.Printf("  JWT algorithm: %s", cfg.JWT.Algorithm)
	log.Printf("  JWT issuer: %s", cfg.JWT.Issuer)
	log.Printf("  JWT audience: %s", cfg.JWT.Audience)
	log.Printf("  JWT kid: %s", cfg.JWT.KeyID)
	log.Printf("  CORS origins: [%s]", cfg.Cors.AllowedOrigins)
	log.Printf("  Server mode: %s", cfg.Server.Mode)
}

// InitLogger creates and configures the logger
func InitLogger(cfg *config.Config) logging.Logger {
	logger := logging.NewLogger(&cfg.Logger)
	logger.Info(logging.General, logging.Startup, "Starting Auth Service", nil)
	return logger
}

// InitMetrics initializes Prometheus metrics
func InitMetrics() {
	metrics.InitMetrics()
}

// InitTracing initializes OpenTelemetry tracing with Tempo
func InitTracing(cfg *config.Config, logger logging.Logger) *commonTracing.Tracer {
	tracingCfg := commonTracing.LoadConfigFromEnv()

	// Map old config if env vars not present
	if !tracingCfg.Enabled && cfg.Tracing.Enabled {
		tracingCfg.Enabled = cfg.Tracing.Enabled
		tracingCfg.ServiceName = cfg.Tracing.ServiceName
		tracingCfg.CollectorURL = cfg.Tracing.JaegerURL
	}

	if !tracingCfg.Enabled {
		logger.Info(logging.General, logging.Startup, "Tracing disabled or not configured", nil)
		return nil
	}

	tp, err := commonTracing.InitTracer(context.Background(), tracingCfg)
	if err != nil {
		logger.Warn(logging.General, logging.Startup, "Failed to initialize tracing, continuing without it", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	logger.Info(logging.General, logging.Startup, "Tracing initialized with Tempo", map[logging.ExtraKey]interface{}{
		"collectorURL": tracingCfg.CollectorURL,
	})

	return tp
}

// ShutdownTracing gracefully shuts down the tracer provider
func ShutdownTracing(tp *commonTracing.Tracer, logger logging.Logger) {
	if tp == nil {
		return
	}

	if err := tp.Shutdown(context.Background()); err != nil {
		logger.Error(logging.General, logging.Startup, "Error shutting down tracer", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	}
}

// InitTranslator initializes i18n translator
func InitTranslator(logger logging.Logger) {
	translator := i18n.GetTranslator()
	if err := translator.LoadTranslations(); err != nil {
		logger.Error(logging.General, logging.Startup, "Failed to load translations", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
	} else {
		logger.Info(logging.General, logging.Startup, "Translations loaded successfully", nil)
	}
}
