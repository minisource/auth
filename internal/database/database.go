package database

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/minisource/auth/config"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

// getEnvOrDefault returns the value of an environment variable or a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// hashSecretFromEnv reads a secret from environment and returns bcrypt hash
func hashSecretFromEnv(key, defaultSecret string) string {
	secret := getEnvOrDefault(key, defaultSecret)
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		// Fallback to default hash if hashing fails
		return ""
	}
	return string(hashedBytes)
}

// InitDatabase initializes the PostgreSQL database connection and runs migrations
func InitDatabase(cfg *config.PostgresConfig, dbCfg *config.DatabaseConfig, logger logging.Logger) (*gorm.DB, error) {
	logger.Info(logging.Postgres, logging.Startup, "Initializing database connection", map[logging.ExtraKey]interface{}{
		"host":   cfg.Host,
		"port":   cfg.Port,
		"dbName": cfg.DbName,
	})

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s TimeZone=UTC",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DbName, cfg.SSLMode,
	)

	// Configure GORM logger
	gormLogLevel := gormLogger.Silent
	if cfg.Host != "" {
		gormLogLevel = gormLogger.Info
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:                 gormLogger.Default.LogMode(gormLogLevel),
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		logger.Error(logging.Postgres, logging.Startup, "Failed to connect to database", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying SQL DB
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(ctx); err != nil {
		logger.Error(logging.Postgres, logging.Startup, "Failed to ping database", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info(logging.Postgres, logging.Startup, "Database connection established", nil)

	// Run migrations if enabled
	if dbCfg.RunMigrations {
		if err := runMigrations(db, dbCfg.RunSeedData, logger); err != nil {
			return nil, err
		}
	} else {
		logger.Info(logging.Postgres, logging.Startup, "Database migrations skipped (disabled in config)", nil)
	}

	return db, nil
}

func runMigrations(db *gorm.DB, runSeedData bool, logger logging.Logger) error {
	logger.Info(logging.Postgres, logging.Migration, "Running database migrations", nil)

	// Enable UUID extension
	db.Exec("CREATE EXTENSION IF NOT EXISTS \"pgcrypto\"")

	// Auto-migrate all models (excluding OTPs and RefreshTokens which are now in Redis)
	err := db.AutoMigrate(
		&models.Tenant{},
		&models.User{},
		&models.Role{},
		&models.Permission{},
		&models.UserRole{},
		&models.RolePermission{},
		&models.Session{},
		// &models.RefreshToken{}, // Now in Redis
		// &models.OTP{}, // Now in Redis
		&models.OAuthAccount{},
		&models.LoginLog{},
		&models.Setting{},
		&models.ServiceClient{},
	)
	if err != nil {
		logger.Error(logging.Postgres, logging.Migration, "Failed to run migrations", map[logging.ExtraKey]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create indexes
	createIndexes(db)

	// Seed default data if enabled
	if runSeedData {
		seedDefaultData(db, logger)
	} else {
		logger.Info(logging.Postgres, logging.Migration, "Database seeding skipped (disabled in config)", nil)
	}

	logger.Info(logging.Postgres, logging.Migration, "Database migrations completed", nil)
	return nil
}

func createIndexes(db *gorm.DB) {
	// Composite indexes
	db.Exec("CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider_id ON oauth_accounts(provider, provider_id)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_login_logs_user_created ON login_logs(user_id, created_at DESC)")
	// Removed OTP indexes as they're now in Redis
}

func seedDefaultData(db *gorm.DB, logger logging.Logger) {
	// Seed default roles
	roles := []models.Role{
		{Name: models.RoleSuperAdmin, DisplayName: "Super Administrator", Description: "Full system access", IsSystem: true},
		{Name: models.RoleAdmin, DisplayName: "Administrator", Description: "Administrative access", IsSystem: true},
		{Name: models.RoleUser, DisplayName: "User", Description: "Standard user access", IsSystem: true},
		{Name: models.RoleGuest, DisplayName: "Guest", Description: "Limited guest access", IsSystem: true},
	}

	for _, role := range roles {
		var existing models.Role
		if db.Where("name = ?", role.Name).First(&existing).Error != nil {
			if err := db.Create(&role).Error; err != nil {
				logger.Debug(logging.Postgres, logging.Migration, "Role already exists", map[logging.ExtraKey]interface{}{
					"role": role.Name,
				})
			} else {
				logger.Info(logging.Postgres, logging.Migration, "Created role", map[logging.ExtraKey]interface{}{
					"role": role.Name,
				})
			}
		}
	}

	// Seed default permissions
	resources := []string{"users", "roles", "permissions", "settings", "sessions", "logs", "notifications", "storage"}
	actions := []string{models.ActionCreate, models.ActionRead, models.ActionUpdate, models.ActionDelete, models.ActionList}

	for _, resource := range resources {
		for _, action := range actions {
			permName := fmt.Sprintf("%s:%s", resource, action)
			var existing models.Permission
			if db.Where("name = ?", permName).First(&existing).Error != nil {
				perm := models.Permission{
					Name:        permName,
					DisplayName: fmt.Sprintf("%s %s", action, resource),
					Resource:    resource,
					Action:      action,
				}
				db.Create(&perm)
			}
		}
	}

	// Seed default settings
	settings := []models.Setting{
		{Key: models.SettingKeyMaxLoginAttempts, Value: "5", Type: "int", Category: models.SettingCategorySecurity, Description: "Maximum failed login attempts before account lock"},
		{Key: models.SettingKeyLockDuration, Value: "30", Type: "int", Category: models.SettingCategorySecurity, Description: "Account lock duration in minutes"},
		{Key: models.SettingKeySessionTimeout, Value: "1440", Type: "int", Category: models.SettingCategorySecurity, Description: "Session timeout in minutes (default 24h)"},
		{Key: models.SettingKeyOTPLength, Value: "4", Type: "int", Category: models.SettingCategoryAuth, Description: "OTP code length"},
		{Key: models.SettingKeyOTPExpiry, Value: "2", Type: "int", Category: models.SettingCategoryAuth, Description: "OTP expiry in minutes"},
		{Key: models.SettingKeyAllowRegistration, Value: "true", Type: "bool", Category: models.SettingCategoryAuth, Description: "Allow new user registration"},
		{Key: models.SettingKeyRequireEmailVerify, Value: "false", Type: "bool", Category: models.SettingCategoryAuth, Description: "Require email verification for login"},
		{Key: models.SettingKeyRequirePhoneVerify, Value: "false", Type: "bool", Category: models.SettingCategoryAuth, Description: "Require phone verification for login"},
		{Key: models.SettingKeyEnableGoogleLogin, Value: "true", Type: "bool", Category: models.SettingCategoryAuth, Description: "Enable Google OAuth login"},
		{Key: models.SettingKeyEnableOTPLogin, Value: "true", Type: "bool", Category: models.SettingCategoryAuth, Description: "Enable OTP-based login"},
		{Key: "password_min_length", Value: "8", Type: "int", Category: models.SettingCategorySecurity, Description: "Minimum password length"},
		{Key: "password_require_uppercase", Value: "true", Type: "bool", Category: models.SettingCategorySecurity, Description: "Require uppercase letter in password"},
		{Key: "password_require_lowercase", Value: "true", Type: "bool", Category: models.SettingCategorySecurity, Description: "Require lowercase letter in password"},
		{Key: "password_require_number", Value: "true", Type: "bool", Category: models.SettingCategorySecurity, Description: "Require number in password"},
		{Key: "password_require_special", Value: "false", Type: "bool", Category: models.SettingCategorySecurity, Description: "Require special character in password"},
	}

	for _, setting := range settings {
		var existing models.Setting
		if db.Where("key = ?", setting.Key).First(&existing).Error != nil {
			db.Create(&setting)
		}
	}

	// Seed service clients for service-to-service authentication
	// Secrets are read from environment variables for security
	serviceClients := []models.ServiceClient{
		{
			Name:         "Auth Service",
			ClientID:     getEnvOrDefault("SERVICE_AUTH_CLIENT_ID", "auth-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_AUTH_CLIENT_SECRET", "auth-service-secret-key"),
			Description:  "Auth service for calling notifier to send OTP, emails, etc.",
			Scopes:       "notifications:send,notifications:read",
			IsActive:     true,
		},
		{
			Name:         "Notifier Service",
			ClientID:     getEnvOrDefault("SERVICE_NOTIFIER_CLIENT_ID", "notifier-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_NOTIFIER_CLIENT_SECRET", "notifier-service-secret-key"),
			Description:  "Notifier service for validating tokens on incoming gRPC/HTTP requests",
			Scopes:       "tokens:validate",
			IsActive:     true,
		},
		{
			Name:         "Gateway Service",
			ClientID:     getEnvOrDefault("SERVICE_GATEWAY_CLIENT_ID", "gateway-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_GATEWAY_CLIENT_SECRET", "gateway-service-secret-key"),
			Description:  "Gateway service for token validation and routing",
			Scopes:       "tokens:validate,users:read",
			IsActive:     true,
		},
		{
			Name:         "Log Service",
			ClientID:     getEnvOrDefault("SERVICE_LOG_CLIENT_ID", "log-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_LOG_CLIENT_SECRET", "log-service-secret-key"),
			Description:  "Log service for receiving and storing logs from other services",
			Scopes:       "tokens:validate,logs:write,logs:read",
			IsActive:     true,
		},
		{
			Name:         "Scheduler Service",
			ClientID:     getEnvOrDefault("SERVICE_SCHEDULER_CLIENT_ID", "scheduler-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_SCHEDULER_CLIENT_SECRET", "scheduler-service-secret-key"),
			Description:  "Scheduler service for job scheduling and execution",
			Scopes:       "tokens:validate,notifications:send,scheduler:admin",
			IsActive:     true,
		},
		{
			Name:         "Storage Service",
			ClientID:     getEnvOrDefault("SERVICE_STORAGE_CLIENT_ID", "storage-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_STORAGE_CLIENT_SECRET", "storage-service-secret-key"),
			Description:  "Storage service for file management with S3 and local storage",
			Scopes:       "tokens:validate,storage:read,storage:write,storage:delete,storage:share,storage:admin",
			IsActive:     true,
		},
		{
			Name:         "Comment Service",
			ClientID:     getEnvOrDefault("SERVICE_COMMENT_CLIENT_ID", "comment-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_COMMENT_CLIENT_SECRET", "comment-service-secret-key"),
			Description:  "Comment service for managing comments, replies, reactions across resources",
			Scopes:       "tokens:validate,notifications:send,comments:read,comments:write,comments:moderate",
			IsActive:     true,
		},
		{
			Name:         "Feedback Service",
			ClientID:     getEnvOrDefault("SERVICE_FEEDBACK_CLIENT_ID", "feedback-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_FEEDBACK_CLIENT_SECRET", "feedback-service-secret-key"),
			Description:  "Feedback service for managing user feedback, voting, and suggestions",
			Scopes:       "tokens:validate,notifications:send,storage:read,storage:write,feedback:read,feedback:write,feedback:admin",
			IsActive:     true,
		},
		{
			Name:         "Ticket Service",
			ClientID:     getEnvOrDefault("SERVICE_TICKET_CLIENT_ID", "ticket-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_TICKET_CLIENT_SECRET", "ticket-service-secret-key"),
			Description:  "Ticket service for support ticket management",
			Scopes:       "tokens:validate,notifications:send,storage:read,storage:write,tickets:read,tickets:write,tickets:admin",
			IsActive:     true,
		},
		{
			Name:         "Payment Service",
			ClientID:     getEnvOrDefault("SERVICE_PAYMENT_CLIENT_ID", "payment-service"),
			ClientSecret: hashSecretFromEnv("SERVICE_PAYMENT_CLIENT_SECRET", "payment-service-secret-key"),
			Description:  "Payment service for payment processing and subscription management",
			Scopes:       "tokens:validate,notifications:send,payments:read,payments:write,payments:admin,subscriptions:read,subscriptions:write",
			IsActive:     true,
		},
	}

	for _, client := range serviceClients {
		var existing models.ServiceClient
		if db.Where("client_id = ?", client.ClientID).First(&existing).Error != nil {
			if err := db.Create(&client).Error; err != nil {
				logger.Debug(logging.Postgres, logging.Migration, "Service client already exists", map[logging.ExtraKey]interface{}{
					"client_id": client.ClientID,
				})
			} else {
				logger.Info(logging.Postgres, logging.Migration, "Created service client", map[logging.ExtraKey]interface{}{
					"client_id": client.ClientID,
				})
			}
		}
	}

	// Seed sysadmin user if credentials are provided in .env
	sysadminEmail := os.Getenv("SYSADMIN_EMAIL")
	sysadminPassword := os.Getenv("SYSADMIN_PASSWORD")
	if sysadminEmail != "" && sysadminPassword != "" {
		var existingSysadmin models.User
		if db.Where("email = ?", sysadminEmail).First(&existingSysadmin).Error != nil {
			// Hash the password using bcrypt
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(sysadminPassword), bcrypt.DefaultCost)
			if err != nil {
				logger.Error(logging.Postgres, logging.Migration, "Failed to hash sysadmin password", map[logging.ExtraKey]interface{}{
					"error": err.Error(),
				})
			} else {
				sysadmin := models.User{
					Email:         sysadminEmail,
					PasswordHash:  string(hashedPassword),
					EmailVerified: true,
					IsActive:      true,
					IsSuperAdmin:  true,
					FirstName:     "System",
					LastName:      "Administrator",
					Username:      "sysadmin",
				}

				if err := db.Create(&sysadmin).Error; err != nil {
					logger.Debug(logging.Postgres, logging.Migration, "Sysadmin user already exists", map[logging.ExtraKey]interface{}{
						"email": sysadminEmail,
					})
				} else {
					// Assign super admin role
					var superAdminRole models.Role
					if db.Where("name = ?", models.RoleSuperAdmin).First(&superAdminRole).Error == nil {
						db.Exec("INSERT INTO user_roles (user_id, role_id) VALUES (?, ?) ON CONFLICT DO NOTHING", sysadmin.ID, superAdminRole.ID)
					}
					logger.Info(logging.Postgres, logging.Migration, "Created sysadmin user", map[logging.ExtraKey]interface{}{
						"email": sysadminEmail,
						"role":  models.RoleSuperAdmin,
					})
				}
			}
		}
	}

	logger.Info(logging.Postgres, logging.Migration, "Default data seeded", nil)
}
