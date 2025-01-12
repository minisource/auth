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
	Server   ServerConfig
	Password common.PasswordConfig
	Redis    cache.RedisConfig
	Cors     CorsConfig
	Logger   logging.LoggerConfig
	Otp      common.OtpConfig
	JWT      JWTConfig
	Hydra	 ory.HydraConfig
}

type ServerConfig struct {
	InternalPort string `env:"SERVER_INTERNAL_PORT"`
	ExternalPort string `env:"SERVER_EXTERNAL_PORT"`
	RunMode      string `env:"SERVER_RUN_MODE"`
}

type PasswordConfig struct {
	IncludeChars     bool `env:"PASSWORD_INCLUDE_CHARS"`
	IncludeDigits    bool `env:"PASSWORD_INCLUDE_DIGITS"`
	MinLength        int  `env:"PASSWORD_MIN_LENGTH"`
	MaxLength        int  `env:"PASSWORD_MAX_LENGTH"`
	IncludeUppercase bool `env:"PASSWORD_INCLUDE_UPPERCASE"`
	IncludeLowercase bool `env:"PASSWORD_INCLUDE_LOWERCASE"`
}

type CorsConfig struct {
	AllowOrigins string `env:"CORS_ALLOW_ORIGINS"`
}

type OtpConfig struct {
	ExpireTime time.Duration `env:"OTP_EXPIRE_TIME"`
	Digits     int           `env:"OTP_DIGITS"`
	Limiter    time.Duration `env:"OTP_LIMITER"`
}

type JWTConfig struct {
	AccessTokenExpireDuration  time.Duration `env:"JWT_ACCESS_TOKEN_EXPIRE_DURATION"`
	RefreshTokenExpireDuration time.Duration `env:"JWT_REFRESH_TOKEN_EXPIRE_DURATION"`
	Secret                     string        `env:"JWT_SECRET"`
	RefreshSecret              string        `env:"JWT_REFRESH_SECRET"`
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
