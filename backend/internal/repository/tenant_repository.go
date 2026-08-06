package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"gorm.io/gorm"
)

type TenantRepository interface {
	Create(ctx context.Context, tenant *models.Tenant) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error)
	GetBySlug(ctx context.Context, slug string) (*models.Tenant, error)
	GetByDomain(ctx context.Context, domain string) (*models.Tenant, error)
	GetDefault(ctx context.Context) (*models.Tenant, error)
	Update(ctx context.Context, tenant *models.Tenant) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, offset, limit int) ([]models.Tenant, int64, error)
	ListByStatus(ctx context.Context, status models.TenantStatus) ([]models.Tenant, error)

	// Member operations
	AddMember(ctx context.Context, member *models.TenantMember) error
	GetMember(ctx context.Context, tenantID, userID uuid.UUID) (*models.TenantMember, error)
	GetMembersByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.TenantMember, error)
	GetMembersByUser(ctx context.Context, userID uuid.UUID) ([]models.TenantMember, error)
	UpdateMember(ctx context.Context, member *models.TenantMember) error
	RemoveMember(ctx context.Context, tenantID, userID uuid.UUID) error
	SetDefaultTenant(ctx context.Context, userID, tenantID uuid.UUID) error

	// Invitation operations
	CreateInvitation(ctx context.Context, invitation *models.TenantInvitation) error
	GetInvitationByToken(ctx context.Context, token string) (*models.TenantInvitation, error)
	GetPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]models.TenantInvitation, error)
	AcceptInvitation(ctx context.Context, id uuid.UUID) error
	DeleteInvitation(ctx context.Context, id uuid.UUID) error
}

type tenantRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewTenantRepository(db *gorm.DB, logger logging.Logger) TenantRepository {
	return &tenantRepository{db: db, logger: logger}
}

func (r *tenantRepository) Create(ctx context.Context, tenant *models.Tenant) error {
	return r.db.WithContext(ctx).Create(tenant).Error
}

func (r *tenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Tenant, error) {
	var tenant models.Tenant
	result := r.db.WithContext(ctx).First(&tenant, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &tenant, nil
}

func (r *tenantRepository) GetBySlug(ctx context.Context, slug string) (*models.Tenant, error) {
	var tenant models.Tenant
	result := r.db.WithContext(ctx).First(&tenant, "slug = ?", slug)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &tenant, nil
}

func (r *tenantRepository) GetByDomain(ctx context.Context, domain string) (*models.Tenant, error) {
	var tenant models.Tenant
	result := r.db.WithContext(ctx).First(&tenant, "domain = ?", domain)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &tenant, nil
}

func (r *tenantRepository) GetDefault(ctx context.Context) (*models.Tenant, error) {
	var tenant models.Tenant
	result := r.db.WithContext(ctx).First(&tenant, "is_default = true")
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &tenant, nil
}

func (r *tenantRepository) Update(ctx context.Context, tenant *models.Tenant) error {
	return r.db.WithContext(ctx).Save(tenant).Error
}

func (r *tenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.Tenant{}, "id = ?", id).Error
}

func (r *tenantRepository) List(ctx context.Context, offset, limit int) ([]models.Tenant, int64, error) {
	var tenants []models.Tenant
	var total int64

	r.db.WithContext(ctx).Model(&models.Tenant{}).Count(&total)
	result := r.db.WithContext(ctx).Offset(offset).Limit(limit).Find(&tenants)
	return tenants, total, result.Error
}

func (r *tenantRepository) ListByStatus(ctx context.Context, status models.TenantStatus) ([]models.Tenant, error) {
	var tenants []models.Tenant
	result := r.db.WithContext(ctx).Where("status = ?", status).Find(&tenants)
	return tenants, result.Error
}

// Member operations
func (r *tenantRepository) AddMember(ctx context.Context, member *models.TenantMember) error {
	return r.db.WithContext(ctx).Create(member).Error
}

func (r *tenantRepository) GetMember(ctx context.Context, tenantID, userID uuid.UUID) (*models.TenantMember, error) {
	var member models.TenantMember
	result := r.db.WithContext(ctx).
		Preload("Tenant").
		Preload("Role").
		First(&member, "tenant_id = ? AND user_id = ?", tenantID, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &member, nil
}

func (r *tenantRepository) GetMembersByTenant(ctx context.Context, tenantID uuid.UUID) ([]models.TenantMember, error) {
	var members []models.TenantMember
	result := r.db.WithContext(ctx).
		Preload("User").
		Preload("Role").
		Where("tenant_id = ?", tenantID).
		Find(&members)
	return members, result.Error
}

func (r *tenantRepository) GetMembersByUser(ctx context.Context, userID uuid.UUID) ([]models.TenantMember, error) {
	var members []models.TenantMember
	result := r.db.WithContext(ctx).
		Preload("Tenant").
		Preload("Role").
		Where("user_id = ?", userID).
		Find(&members)
	return members, result.Error
}

func (r *tenantRepository) UpdateMember(ctx context.Context, member *models.TenantMember) error {
	return r.db.WithContext(ctx).Save(member).Error
}

func (r *tenantRepository) RemoveMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("tenant_id = ? AND user_id = ?", tenantID, userID).
		Delete(&models.TenantMember{}).Error
}

func (r *tenantRepository) SetDefaultTenant(ctx context.Context, userID, tenantID uuid.UUID) error {
	// Clear existing default
	r.db.WithContext(ctx).Model(&models.TenantMember{}).
		Where("user_id = ?", userID).
		Update("is_default", false)

	// Set new default
	return r.db.WithContext(ctx).Model(&models.TenantMember{}).
		Where("user_id = ? AND tenant_id = ?", userID, tenantID).
		Update("is_default", true).Error
}

// Invitation operations
func (r *tenantRepository) CreateInvitation(ctx context.Context, invitation *models.TenantInvitation) error {
	return r.db.WithContext(ctx).Create(invitation).Error
}

func (r *tenantRepository) GetInvitationByToken(ctx context.Context, token string) (*models.TenantInvitation, error) {
	var invitation models.TenantInvitation
	result := r.db.WithContext(ctx).
		Preload("Tenant").
		First(&invitation, "token = ? AND accepted_at IS NULL", token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &invitation, nil
}

func (r *tenantRepository) GetPendingInvitations(ctx context.Context, tenantID uuid.UUID) ([]models.TenantInvitation, error) {
	var invitations []models.TenantInvitation
	result := r.db.WithContext(ctx).
		Where("tenant_id = ? AND accepted_at IS NULL", tenantID).
		Find(&invitations)
	return invitations, result.Error
}

func (r *tenantRepository) AcceptInvitation(ctx context.Context, id uuid.UUID) error {
	now := gorm.Expr("NOW()")
	return r.db.WithContext(ctx).Model(&models.TenantInvitation{}).
		Where("id = ?", id).
		Update("accepted_at", now).Error
}

func (r *tenantRepository) DeleteInvitation(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.TenantInvitation{}, "id = ?", id).Error
}
