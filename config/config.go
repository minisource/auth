package config

import (
	"fmt"
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
	Server        ServerConfig
	Postgres      PostgresConfig
	Redis         RedisConfig
	JWT           JWTConfig
	OTP           OTPConfig
	Password      PasswordConfig
	Google        GoogleOAuthConfig
	RateLimit     RateLimitConfig
	Introspection IntrospectionConfig
	Cors          CorsConfig
	Logger        logging.LoggerConfig
	Notifier      NotifierConfig
	GRPC          GRPCConfig
	Database      DatabaseConfig
	Tracing       TracingConfig
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
	Algorithm     string // "HS256" or "RS256"
	Audience      string // Default audience for tokens
	KeyID         string // Key ID for JWKS kid header
	PrivateKeyPath  string
	PublicKeyPath   string
	PrivateKeyPEM   string
	PublicKeyPEM    string
	AllowHS256InProduction bool
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
	MockEnabled  bool
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
}

type RateLimitConfig struct {
	LoginPerMinute          int
	OTPPerMinute            int
	PasswordResetPerHour    int
	RegisterPerMinute       int
}

type IntrospectionConfig struct {
	RequireServiceAuth bool
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
	AuthURL      string // Optional override URL for token auth requests
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
				Algorithm:     getEnv("JWT_ALGORITHM", "HS256"),
				Audience:      getEnv("JWT_AUDIENCE", "minisource"),
				KeyID:         getEnv("JWT_KEY_ID", "auth-key-1"),
				PrivateKeyPath:  getEnv("JWT_PRIVATE_KEY_PATH", ""),
				PublicKeyPath:   getEnv("JWT_PUBLIC_KEY_PATH", ""),
				PrivateKeyPEM:   getEnv("JWT_PRIVATE_KEY_PEM", ""),
				PublicKeyPEM:    getEnv("JWT_PUBLIC_KEY_PEM", ""),
				AllowHS256InProduction: getEnvAsBool("AUTH_ALLOW_HS256_IN_PRODUCTION", false),
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
				MockEnabled:  getEnvAsBool("GOOGLE_MOCK_ENABLED", false),
				AuthURL:      getEnv("GOOGLE_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth"),
				TokenURL:     getEnv("GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token"),
				UserInfoURL:  getEnv("GOOGLE_USERINFO_URL", "https://www.googleapis.com/oauth2/v2/userinfo"),
			},
			RateLimit: RateLimitConfig{
				LoginPerMinute:       getEnvAsInt("AUTH_LOGIN_RATE_LIMIT_PER_MINUTE", 5),
				OTPPerMinute:         getEnvAsInt("AUTH_OTP_RATE_LIMIT_PER_MINUTE", 3),
				PasswordResetPerHour: getEnvAsInt("AUTH_PASSWORD_RESET_RATE_LIMIT_PER_HOUR", 5),
				RegisterPerMinute:    getEnvAsInt("AUTH_REGISTER_RATE_LIMIT_PER_MINUTE", 3),
			},
			Introspection: IntrospectionConfig{
				RequireServiceAuth: getEnvAsBool("AUTH_INTROSPECTION_REQUIRE_SERVICE_AUTH", true),
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
				AuthURL:      getEnv("NOTIFIER_AUTH_URL", ""),
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

func (c *Config) IsProduction() bool {
	return c.Server.Mode == "production"
}

// Validate checks configuration for security and consistency.
// Returns an error if the configuration is invalid for the current environment.
func (c *Config) Validate() error {
	if c.IsProduction() {
		return c.validateProduction()
	}
	return c.validateDevelopment()
}

func (c *Config) validateProduction() error {
	// JWT secret must not be the default
	if c.JWT.Secret == "change-me-in-production" {
		return fmt.Errorf("JWT_SECRET must be set to a secure value in production (current: default placeholder)")
	}

	// Algorithm must be set
	if c.JWT.Algorithm == "" {
		return fmt.Errorf("JWT_ALGORITHM must be set in production")
	}

	// Only RS256 allowed in production unless explicitly overridden
	if c.JWT.Algorithm != "RS256" && c.JWT.Algorithm != "EdDSA" {
		if !c.JWT.AllowHS256InProduction {
			return fmt.Errorf("JWT_ALGORITHM=%s is not allowed in production; use RS256 or set AUTH_ALLOW_HS256_IN_PRODUCTION=true", c.JWT.Algorithm)
		}
		log.Println("WARNING: HS256 is enabled in production via AUTH_ALLOW_HS256_IN_PRODUCTION=true")
	}

	// RS256 requires key pair
	if c.JWT.Algorithm == "RS256" {
		if c.JWT.PrivateKeyPEM == "" && c.JWT.PrivateKeyPath == "" {
			return fmt.Errorf("RS256 requires JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM in production")
		}
		if c.JWT.PublicKeyPEM == "" && c.JWT.PublicKeyPath == "" {
			return fmt.Errorf("RS256 requires JWT_PUBLIC_KEY_PATH or JWT_PUBLIC_KEY_PEM in production")
		}
	}

	// Issuer must be set
	if c.JWT.Issuer == "" {
		return fmt.Errorf("JWT_ISSUER must be set")
	}

	// Audience must be set
	if c.JWT.Audience == "" {
		return fmt.Errorf("JWT_AUDIENCE must be set")
	}

	return nil
}

func (c *Config) validateDevelopment() error {
	// In development, RS256 keys are optional (HS256 fallback works)
	if c.JWT.Algorithm == "RS256" {
		if c.JWT.PrivateKeyPEM == "" && c.JWT.PrivateKeyPath == "" {
			return fmt.Errorf("RS256 requires JWT_PRIVATE_KEY_PATH or JWT_PRIVATE_KEY_PEM")
		}
	}
	return nil
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
