package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"gorm.io/gorm"
)

type PasskeyRepository interface {
	Create(ctx context.Context, passkey *models.Passkey) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Passkey, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]models.Passkey, error)
	GetByCredentialID(ctx context.Context, credentialID string) (*models.Passkey, error)
	Update(ctx context.Context, passkey *models.Passkey) error
	Delete(ctx context.Context, id uuid.UUID) error
}

type passkeyRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewPasskeyRepository(db *gorm.DB, logger logging.Logger) PasskeyRepository {
	return &passkeyRepository{db: db, logger: logger}
}

func (r *passkeyRepository) Create(ctx context.Context, passkey *models.Passkey) error {
	return r.db.WithContext(ctx).Create(passkey).Error
}

func (r *passkeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Passkey, error) {
	var passkey models.Passkey
	result := r.db.WithContext(ctx).First(&passkey, "id = ?", id)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, result.Error
	}
	return &passkey, nil
}

func (r *passkeyRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]models.Passkey, error) {
	var passkeys []models.Passkey
	result := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&passkeys)
	if result.Error != nil {
		return nil, result.Error
	}
	return passkeys, nil
}

func (r *passkeyRepository) GetByCredentialID(ctx context.Context, credentialID string) (*models.Passkey, error) {
	var passkey models.Passkey
	result := r.db.WithContext(ctx).First(&passkey, "credential_id = ?", credentialID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, result.Error
	}
	return &passkey, nil
}

func (r *passkeyRepository) Update(ctx context.Context, passkey *models.Passkey) error {
	return r.db.WithContext(ctx).Save(passkey).Error
}

func (r *passkeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.Passkey{}, "id = ?", id).Error
}
