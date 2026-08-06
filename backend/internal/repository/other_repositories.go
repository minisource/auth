package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"gorm.io/gorm"
)

type LoginLogRepository interface {
	Create(ctx context.Context, log *models.LoginLog) error
	GetByUserID(ctx context.Context, userID uuid.UUID, limit int) ([]models.LoginLog, error)
	GetByAction(ctx context.Context, action string, limit int) ([]models.LoginLog, error)
	GetByIPAddress(ctx context.Context, ip string, since time.Time) ([]models.LoginLog, error)
	CountFailedAttempts(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error)
	DeleteOld(ctx context.Context, before time.Time) error
}

type loginLogRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewLoginLogRepository(db *gorm.DB, logger logging.Logger) LoginLogRepository {
	return &loginLogRepository{db: db, logger: logger}
}

func (r *loginLogRepository) Create(ctx context.Context, log *models.LoginLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

func (r *loginLogRepository) GetByUserID(ctx context.Context, userID uuid.UUID, limit int) ([]models.LoginLog, error) {
	var logs []models.LoginLog
	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs)
	return logs, result.Error
}

func (r *loginLogRepository) GetByAction(ctx context.Context, action string, limit int) ([]models.LoginLog, error) {
	var logs []models.LoginLog
	result := r.db.WithContext(ctx).
		Where("action = ?", action).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs)
	return logs, result.Error
}

func (r *loginLogRepository) GetByIPAddress(ctx context.Context, ip string, since time.Time) ([]models.LoginLog, error) {
	var logs []models.LoginLog
	result := r.db.WithContext(ctx).
		Where("ip_address = ? AND created_at > ?", ip, since).
		Order("created_at DESC").
		Find(&logs)
	return logs, result.Error
}

func (r *loginLogRepository) CountFailedAttempts(ctx context.Context, userID uuid.UUID, since time.Time) (int64, error) {
	var count int64
	result := r.db.WithContext(ctx).Model(&models.LoginLog{}).
		Where("user_id = ? AND action = ? AND success = false AND created_at > ?",
			userID, models.LoginActionLoginFailed, since).
		Count(&count)
	return count, result.Error
}

func (r *loginLogRepository) DeleteOld(ctx context.Context, before time.Time) error {
	return r.db.WithContext(ctx).Where("created_at < ?", before).Delete(&models.LoginLog{}).Error
}

// SettingRepository
type SettingRepository interface {
	Get(ctx context.Context, key string) (*models.Setting, error)
	GetByCategory(ctx context.Context, category string) ([]models.Setting, error)
	GetAll(ctx context.Context) ([]models.Setting, error)
	GetPublic(ctx context.Context) ([]models.Setting, error)
	Set(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
}

type settingRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewSettingRepository(db *gorm.DB, logger logging.Logger) SettingRepository {
	return &settingRepository{db: db, logger: logger}
}

func (r *settingRepository) Get(ctx context.Context, key string) (*models.Setting, error) {
	var setting models.Setting
	result := r.db.WithContext(ctx).First(&setting, "key = ?", key)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &setting, nil
}

func (r *settingRepository) GetByCategory(ctx context.Context, category string) ([]models.Setting, error) {
	var settings []models.Setting
	result := r.db.WithContext(ctx).Where("category = ?", category).Find(&settings)
	return settings, result.Error
}

func (r *settingRepository) GetAll(ctx context.Context) ([]models.Setting, error) {
	var settings []models.Setting
	result := r.db.WithContext(ctx).Find(&settings)
	return settings, result.Error
}

func (r *settingRepository) GetPublic(ctx context.Context) ([]models.Setting, error) {
	var settings []models.Setting
	result := r.db.WithContext(ctx).Where("is_public = true").Find(&settings)
	return settings, result.Error
}

func (r *settingRepository) Set(ctx context.Context, key, value string) error {
	return r.db.WithContext(ctx).Model(&models.Setting{}).
		Where("key = ?", key).
		Update("value", value).Error
}

func (r *settingRepository) Delete(ctx context.Context, key string) error {
	return r.db.WithContext(ctx).Delete(&models.Setting{}, "key = ?", key).Error
}

// OAuthAccountRepository
type OAuthAccountRepository interface {
	Create(ctx context.Context, account *models.OAuthAccount) error
	GetByProviderID(ctx context.Context, provider, providerID string) (*models.OAuthAccount, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]models.OAuthAccount, error)
	Update(ctx context.Context, account *models.OAuthAccount) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByUserAndProvider(ctx context.Context, userID uuid.UUID, provider string) error
}

type oauthAccountRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewOAuthAccountRepository(db *gorm.DB, logger logging.Logger) OAuthAccountRepository {
	return &oauthAccountRepository{db: db, logger: logger}
}

func (r *oauthAccountRepository) Create(ctx context.Context, account *models.OAuthAccount) error {
	return r.db.WithContext(ctx).Create(account).Error
}

func (r *oauthAccountRepository) GetByProviderID(ctx context.Context, provider, providerID string) (*models.OAuthAccount, error) {
	var account models.OAuthAccount
	result := r.db.WithContext(ctx).First(&account, "provider = ? AND provider_id = ?", provider, providerID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &account, nil
}

func (r *oauthAccountRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]models.OAuthAccount, error) {
	var accounts []models.OAuthAccount
	result := r.db.WithContext(ctx).Where("user_id = ?", userID).Find(&accounts)
	return accounts, result.Error
}

func (r *oauthAccountRepository) Update(ctx context.Context, account *models.OAuthAccount) error {
	return r.db.WithContext(ctx).Save(account).Error
}

func (r *oauthAccountRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.OAuthAccount{}, "id = ?", id).Error
}

func (r *oauthAccountRepository) DeleteByUserAndProvider(ctx context.Context, userID uuid.UUID, provider string) error {
	return r.db.WithContext(ctx).Delete(&models.OAuthAccount{}, "user_id = ? AND provider = ?", userID, provider).Error
}

// RefreshTokenRepository
// RefreshTokenRepository moved to refresh_token_repository.go (Redis-only implementation)
