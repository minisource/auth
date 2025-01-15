package config

import (
	"log"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/minisource/common_go/common"
	"github.com/minisource/common_go/db/cache"
	"github.com/minisource/common_go/logging"
	"github.com/minisource/common_go/ory"
)

type Config struct {
	Server             ServerConfig
	Redis              cache.RedisConfig
	Cors               CorsConfig
	Logger             logging.LoggerConfig
	Otp                common.OtpConfig
	Hydra              ory.HydraConfig
	Kratos             ory.KratosConfig
	OAuthUrl           string `env:"APICLIENTS_OAUTH_URL"`
	NotificationConfig NotificationConfig
}

type ServerConfig struct {
	InternalPort string `env:"SERVER_INTERNAL_PORT"`
	ExternalPort string `env:"SERVER_EXTERNAL_PORT"`
	RunMode      string `env:"SERVER_RUN_MODE"`
	Name         string `env:"SERVER_NAME"`
}

type NotificationConfig struct {
	Url          string `env:"APICLIENTS_NOTIFICATION_URL"`
	ClientId     string `env:"APICLIENTS_NOTIFICATION_CLIENTID"`
	ClientSecret string `env:"APICLIENTS_NOTIFICATION_SECRET"`
	TemplateOTP  string `env:"APICLIENTS_NOTIFICATION_TEMPLATE_OTP"`
}

type CorsConfig struct {
	AllowOrigins string `env:"CORS_ALLOW_ORIGINS"`
}

type OtpConfig struct {
	ExpireTime time.Duration `env:"OTP_EXPIRE_TIME"`
	Digits     int           `env:"OTP_DIGITS"`
	Limiter    time.Duration `env:"OTP_LIMITER"`
}

// LoadConfig loads configuration from environment variables
func GetConfig() *Config {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		log.Fatalf("Error in parse config %v", err)
		panic(err)
	}

	return cfg
}
