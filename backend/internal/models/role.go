package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Role represents a role in the system
type Role struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID    *uuid.UUID     `gorm:"type:uuid;index" json:"tenantId,omitempty"` // nil = system-wide role
	Name        string         `gorm:"size:100;not null;index:idx_tenant_role_name,unique" json:"name"`
	DisplayName string         `gorm:"size:200" json:"displayName"`
	Description string         `gorm:"size:500" json:"description,omitempty"`
	IsSystem    bool           `gorm:"default:false" json:"isSystem"` // System roles cannot be deleted
	IsActive    bool           `gorm:"default:true" json:"isActive"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Tenant      *Tenant      `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
	Users       []User       `gorm:"many2many:user_roles;" json:"-"`
}

func (r *Role) TableName() string {
	return "roles"
}

// Permission represents a permission in the system
type Permission struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string         `gorm:"uniqueIndex;size:100;not null" json:"name"`
	DisplayName string         `gorm:"size:200" json:"displayName"`
	Description string         `gorm:"size:500" json:"description,omitempty"`
	Resource    string         `gorm:"size:100;index" json:"resource"`
	Action      string         `gorm:"size:50;index" json:"action"`
	IsActive    bool           `gorm:"default:true" json:"isActive"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Roles []Role `gorm:"many2many:role_permissions;" json:"-"`
}

func (p *Permission) TableName() string {
	return "permissions"
}

// Common role names
const (
	RoleSuperAdmin = "super_admin"
	RoleAdmin      = "admin"
	RoleUser       = "user"
	RoleGuest      = "guest"
	RoleService    = "service"
)

// Common permission actions
const (
	ActionCreate = "create"
	ActionRead   = "read"
	ActionUpdate = "update"
	ActionDelete = "delete"
	ActionList   = "list"
	ActionManage = "manage"
)

// UserRole is the join table for users and roles
type UserRole struct {
	UserID    uuid.UUID `gorm:"type:uuid;primaryKey"`
	RoleID    uuid.UUID `gorm:"type:uuid;primaryKey"`
	CreatedAt time.Time
}

func (UserRole) TableName() string {
	return "user_roles"
}

// RolePermission is the join table for roles and permissions
type RolePermission struct {
	RoleID       uuid.UUID `gorm:"type:uuid;primaryKey"`
	PermissionID uuid.UUID `gorm:"type:uuid;primaryKey"`
	CreatedAt    time.Time
}

func (RolePermission) TableName() string {
	return "role_permissions"
}
