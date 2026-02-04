package config

import (
	"log"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/minisource/go-common/logging"
)

var (
	cfg  *Config
	once sync.Once
)

type Config struct {
	Server   ServerConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	JWT      JWTConfig
	OTP      OTPConfig
	Password PasswordConfig
	Google   GoogleOAuthConfig
	Cors     CorsConfig
	Logger   logging.LoggerConfig
	Notifier NotifierConfig
	GRPC     GRPCConfig
	Database DatabaseConfig
	Tracing  TracingConfig
}

type ServerConfig struct {
	Port string
	Mode string
	Name string
}

type PostgresConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	DbName          string
	SSLMode         string
	MaxIdleConns    int
	MaxOpenConns    int
	ConnMaxLifetime time.Duration
}

type DatabaseConfig struct {
	RunMigrations bool
	RunSeedData   bool
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type JWTConfig struct {
	Secret        string
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	Issuer        string
}

type OTPConfig struct {
	Length      int
	Expiry      time.Duration
	MaxAttempts int
}

type PasswordConfig struct {
	MinLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumber    bool
	RequireSpecial   bool
}

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type CorsConfig struct {
	AllowedOrigins string
}

type NotifierConfig struct {
	Enabled      bool
	GRPCAddress  string
	HTTPURL      string
	ClientID     string // Service client ID for auth (if required by notifier)
	ClientSecret string // Service client secret for auth (if required by notifier)
}

type GRPCConfig struct {
	Enabled bool
	Port    string
}

type TracingConfig struct {
	Enabled     bool
	JaegerURL   string
	ServiceName string
}

func GetConfig() *Config {
	once.Do(func() {
		if err := godotenv.Load(); err != nil {
			log.Println("No .env file found, using environment variables")
		}

		cfg = &Config{
			Server: ServerConfig{
				Port: getEnv("SERVER_PORT", "9001"),
				Mode: getEnv("SERVER_MODE", "development"),
				Name: getEnv("SERVER_NAME", "auth-service"),
			},
			Postgres: PostgresConfig{
				Host:            getEnv("DB_HOST", "localhost"),
				Port:            getEnv("DB_PORT", "5432"),
				User:            getEnv("DB_USER", "postgres"),
				Password:        getEnv("DB_PASSWORD", "postgres"),
				DbName:          getEnv("DB_NAME", "auth_db"),
				SSLMode:         getEnv("DB_SSLMODE", "disable"),
				MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 10),
				MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 100),
				ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", time.Hour),
			},
			Redis: RedisConfig{
				Host:     getEnv("REDIS_HOST", "localhost"),
				Port:     getEnv("REDIS_PORT", "6379"),
				Password: getEnv("REDIS_PASSWORD", ""),
				DB:       getEnvAsInt("REDIS_DB", 0),
			},
			JWT: JWTConfig{
				Secret:        getEnv("JWT_SECRET", "change-me-in-production"),
				AccessExpiry:  getEnvAsDuration("JWT_ACCESS_EXPIRY", 15*time.Minute),
				RefreshExpiry: getEnvAsDuration("JWT_REFRESH_EXPIRY", 168*time.Hour),
				Issuer:        getEnv("JWT_ISSUER", "minisource-auth"),
			},
			OTP: OTPConfig{
				Length:      getEnvAsInt("OTP_LENGTH", 6),
				Expiry:      getEnvAsDuration("OTP_EXPIRY", 5*time.Minute),
				MaxAttempts: getEnvAsInt("OTP_MAX_ATTEMPTS", 5),
			},
			Password: PasswordConfig{
				MinLength:        getEnvAsInt("PASSWORD_MIN_LENGTH", 8),
				RequireUppercase: getEnvAsBool("PASSWORD_REQUIRE_UPPERCASE", true),
				RequireLowercase: getEnvAsBool("PASSWORD_REQUIRE_LOWERCASE", true),
				RequireNumber:    getEnvAsBool("PASSWORD_REQUIRE_NUMBER", true),
				RequireSpecial:   getEnvAsBool("PASSWORD_REQUIRE_SPECIAL", false),
			},
			Google: GoogleOAuthConfig{
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:9001/api/v1/auth/google/callback"),
			},
			Cors: CorsConfig{
				AllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "*"),
			},
			Logger: logging.LoggerConfig{
				FilePath:    getEnv("LOG_FILE_PATH", "./logs/"),
				Encoding:    getEnv("LOG_ENCODING", "json"),
				Level:       getEnv("LOG_LEVEL", "debug"),
				Logger:      getEnv("LOG_LOGGER", "zap"),
				ConsoleOnly: getEnvAsBool("LOG_CONSOLE_ONLY", false),
			},
			Notifier: NotifierConfig{
				Enabled:      getEnvAsBool("NOTIFIER_ENABLED", true),
				GRPCAddress:  getEnv("NOTIFIER_GRPC_ADDRESS", "localhost:9003"),
				HTTPURL:      getEnv("NOTIFIER_HTTP_URL", "http://localhost:9002"),
				ClientID:     getEnv("NOTIFIER_CLIENT_ID", "auth-service"),
				ClientSecret: getEnv("NOTIFIER_CLIENT_SECRET", ""),
			},
			GRPC: GRPCConfig{
				Enabled: getEnvAsBool("GRPC_ENABLED", true),
				Port:    getEnv("GRPC_PORT", "9004"),
			},
			Database: DatabaseConfig{
				RunMigrations: getEnvAsBool("DB_RUN_MIGRATIONS", true),
				RunSeedData:   getEnvAsBool("DB_RUN_SEED_DATA", true),
			},
			Tracing: TracingConfig{
				Enabled:     getEnvAsBool("TRACING_ENABLED", false),
				JaegerURL:   getEnv("JAEGER_URL", "http://localhost:14268/api/traces"),
				ServiceName: getEnv("TRACING_SERVICE_NAME", "auth-service"),
			},
		}
	})

	return cfg
}

func (c *Config) IsDevelopment() bool {
	return c.Server.Mode == "development"
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value, exists := os.LookupEnv(key); exists {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
