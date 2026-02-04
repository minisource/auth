package initializer

import (
	"context"

	"github.com/minisource/auth/config"
	"github.com/minisource/auth/pkg/tracing"
	"github.com/minisource/go-common/i18n"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/metrics"
	"go.opentelemetry.io/otel/sdk/trace"
)

// InitConfig loads configuration from environment
func InitConfig() *config.Config {
	return config.GetConfig()
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

// InitTracing initializes OpenTelemetry tracing with Jaeger
func InitTracing(cfg *config.Config, logger logging.Logger) *trace.TracerProvider {
	if !cfg.Tracing.Enabled || cfg.Tracing.JaegerURL == "" {
		logger.Info(logging.General, logging.Startup, "Tracing disabled or not configured", nil)
		return nil
	}

	tp, err := tracing.InitTracer(cfg.Tracing.ServiceName, cfg.Tracing.JaegerURL)
	if err != nil {
		logger.Warn(logging.General, logging.Startup, "Failed to initialize tracing, continuing without it", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	logger.Info(logging.General, logging.Startup, "Tracing initialized with Jaeger", map[logging.ExtraKey]interface{}{
		"jaegerURL": cfg.Tracing.JaegerURL,
	})

	return tp
}

// ShutdownTracing gracefully shuts down the tracer provider
func ShutdownTracing(tp *trace.TracerProvider, logger logging.Logger) {
	if tp == nil {
		return
	}

	if err := tracing.Shutdown(context.Background(), tp); err != nil {
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
