package repository

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/go-common/logging"
	"gorm.io/gorm"
)

type RoleRepository interface {
	Create(ctx context.Context, role *models.Role) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error)
	GetByName(ctx context.Context, name string) (*models.Role, error)
	Update(ctx context.Context, role *models.Role) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]models.Role, error)
	GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.Role, error)
	AssignPermission(ctx context.Context, roleID, permissionID uuid.UUID) error
	RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID) error
	HasPermission(ctx context.Context, roleID uuid.UUID, permissionName string) (bool, error)
}

type roleRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewRoleRepository(db *gorm.DB, logger logging.Logger) RoleRepository {
	return &roleRepository{db: db, logger: logger}
}

func (r *roleRepository) Create(ctx context.Context, role *models.Role) error {
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *roleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	var role models.Role
	result := r.db.WithContext(ctx).First(&role, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &role, nil
}

func (r *roleRepository) GetByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	result := r.db.WithContext(ctx).First(&role, "name = ?", name)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &role, nil
}

func (r *roleRepository) Update(ctx context.Context, role *models.Role) error {
	return r.db.WithContext(ctx).Save(role).Error
}

func (r *roleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.Role{}, "id = ?", id).Error
}

func (r *roleRepository) List(ctx context.Context) ([]models.Role, error) {
	var roles []models.Role
	result := r.db.WithContext(ctx).Where("is_active = true").Find(&roles)
	return roles, result.Error
}

func (r *roleRepository) GetWithPermissions(ctx context.Context, id uuid.UUID) (*models.Role, error) {
	var role models.Role
	result := r.db.WithContext(ctx).Preload("Permissions").First(&role, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &role, nil
}

func (r *roleRepository) AssignPermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	rolePerm := models.RolePermission{RoleID: roleID, PermissionID: permissionID}
	return r.db.WithContext(ctx).Create(&rolePerm).Error
}

func (r *roleRepository) RemovePermission(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return r.db.WithContext(ctx).
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&models.RolePermission{}).Error
}

func (r *roleRepository) HasPermission(ctx context.Context, roleID uuid.UUID, permissionName string) (bool, error) {
	var count int64
	result := r.db.WithContext(ctx).Table("role_permissions rp").
		Joins("JOIN permissions p ON rp.permission_id = p.id").
		Where("rp.role_id = ? AND p.name = ?", roleID, permissionName).
		Count(&count)
	return count > 0, result.Error
}

// PermissionRepository
type PermissionRepository interface {
	Create(ctx context.Context, permission *models.Permission) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error)
	GetByName(ctx context.Context, name string) (*models.Permission, error)
	Update(ctx context.Context, permission *models.Permission) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context) ([]models.Permission, error)
	ListByResource(ctx context.Context, resource string) ([]models.Permission, error)
}

type permissionRepository struct {
	db     *gorm.DB
	logger logging.Logger
}

func NewPermissionRepository(db *gorm.DB, logger logging.Logger) PermissionRepository {
	return &permissionRepository{db: db, logger: logger}
}

func (r *permissionRepository) Create(ctx context.Context, permission *models.Permission) error {
	return r.db.WithContext(ctx).Create(permission).Error
}

func (r *permissionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Permission, error) {
	var permission models.Permission
	result := r.db.WithContext(ctx).First(&permission, "id = ?", id)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &permission, nil
}

func (r *permissionRepository) GetByName(ctx context.Context, name string) (*models.Permission, error) {
	var permission models.Permission
	result := r.db.WithContext(ctx).First(&permission, "name = ?", name)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &permission, nil
}

func (r *permissionRepository) List(ctx context.Context) ([]models.Permission, error) {
	var permissions []models.Permission
	result := r.db.WithContext(ctx).Where("is_active = true").Find(&permissions)
	return permissions, result.Error
}

func (r *permissionRepository) ListByResource(ctx context.Context, resource string) ([]models.Permission, error) {
	var permissions []models.Permission
	result := r.db.WithContext(ctx).Where("resource = ? AND is_active = true", resource).Find(&permissions)
	return permissions, result.Error
}

func (r *permissionRepository) Update(ctx context.Context, permission *models.Permission) error {
	return r.db.WithContext(ctx).Save(permission).Error
}

func (r *permissionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return r.db.WithContext(ctx).Delete(&models.Permission{}, "id = ?", id).Error
}
