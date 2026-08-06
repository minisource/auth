package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"gorm.io/gorm"
)

type OAuthProviderRepository interface {
	Create(ctx context.Context, provider *models.OAuthProvider) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthProvider, error)
	List(ctx context.Context, tenantID *uuid.UUID, offset, limit int) ([]models.OAuthProvider, int64, error)
	Update(ctx context.Context, provider *models.OAuthProvider) error
	Delete(ctx context.Context, id uuid.UUID) error
	GetByType(ctx context.Context, providerType string, tenantID *uuid.UUID) (*models.OAuthProvider, error)
	IncrementStats(ctx context.Context, id uuid.UUID, successful bool) error
}

type oauthProviderRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewOAuthProviderRepository(db *gorm.DB, logger logging.Logger) OAuthProviderRepository {
	return &oauthProviderRepository{db: db, logger: logger}
}

func (r *oauthProviderRepository) Create(ctx context.Context, provider *models.OAuthProvider) error {
	return r.db.WithContext(ctx).Create(provider).Error
}

func (r *oauthProviderRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.OAuthProvider, error) {
	var provider models.OAuthProvider
	result := r.db.WithContext(ctx).Preload("Tenant").First(&provider, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &provider, nil
}

func (r *oauthProviderRepository) List(ctx context.Context, tenantID *uuid.UUID, offset, limit int) ([]models.OAuthProvider, int64, error) {
	var providers []models.OAuthProvider
	var total int64

	query := r.db.WithContext(ctx).Model(&models.OAuthProvider{})
	if tenantID != nil && *tenantID != uuid.Nil {
		// Tenant view includes tenant-scoped providers plus shared global ones
		query = query.Where("(tenant_id = ? OR tenant_id IS NULL)", *tenantID)
	}
	// nil tenantID => "all tenants" view: no filter

	query.Count(&total)
	result := query.Preload("Tenant").Offset(offset).Limit(limit).Order("created_at DESC").Find(&providers)
	return providers, total, result.Error
}

func (r *oauthProviderRepository) Update(ctx context.Context, provider *models.OAuthProvider) error {
	return r.db.WithContext(ctx).Save(provider).Error
}

func (r *oauthProviderRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.OAuthProvider{}, "id = ?", id).Error
}

func (r *oauthProviderRepository) GetByType(ctx context.Context, providerType string, tenantID *uuid.UUID) (*models.OAuthProvider, error) {
	var provider models.OAuthProvider
	query := r.db.WithContext(ctx).Where("type = ? AND is_enabled = true", providerType)
	if tenantID != nil && *tenantID != uuid.Nil {
		// Prefer tenant-scoped provider, fall back to shared global one
		query = query.Where("(tenant_id = ? OR tenant_id IS NULL)", *tenantID).
			Order("CASE WHEN tenant_id IS NULL THEN 1 ELSE 0 END")
	} else {
		query = query.Where("tenant_id IS NULL")
	}
	result := query.First(&provider)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &provider, nil
}

func (r *oauthProviderRepository) IncrementStats(ctx context.Context, id uuid.UUID, successful bool) error {
	updates := map[string]interface{}{
		"total_logins": gorm.Expr("total_logins + 1"),
		"last_used_at": gorm.Expr("NOW()"),
	}
	if successful {
		updates["successful_logins"] = gorm.Expr("successful_logins + 1")
	} else {
		updates["failed_logins"] = gorm.Expr("failed_logins + 1")
	}
	return r.db.WithContext(ctx).Model(&models.OAuthProvider{}).Where("id = ?", id).Updates(updates).Error
}
