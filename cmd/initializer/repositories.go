package initializer

import (
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/go-common/logging"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

// Repositories holds all repository instances
type Repositories struct {
	User          repository.UserRepository
	Session       repository.SessionRepository
	OTP           repository.OTPRepository
	Role          repository.RoleRepository
	Permission    repository.PermissionRepository
	LoginLog      repository.LoginLogRepository
	Setting       repository.SettingRepository
	OAuth         repository.OAuthAccountRepository
	RefreshToken  repository.RefreshTokenRepository
	ServiceClient repository.ServiceClientRepository
}

// InitRepositories creates all repository instances
func InitRepositories(db *gorm.DB, rdb *redis.Client, logger logging.Logger) *Repositories {
	return &Repositories{
		User:          repository.NewUserRepository(db, logger),
		Session:       repository.NewSessionRepository(db, rdb, logger),
		OTP:           repository.NewOTPRepository(rdb, logger),
		Role:          repository.NewRoleRepository(db, logger),
		Permission:    repository.NewPermissionRepository(db, logger),
		LoginLog:      repository.NewLoginLogRepository(db, logger),
		Setting:       repository.NewSettingRepository(db, logger),
		OAuth:         repository.NewOAuthAccountRepository(db, logger),
		RefreshToken:  repository.NewRefreshTokenRepository(rdb, logger),
		ServiceClient: repository.NewServiceClientRepository(db, rdb, logger),
	}
}
