package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID             uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID       *uuid.UUID     `gorm:"type:uuid;index" json:"tenantId,omitempty"` // Current/default tenant
	Email          string         `gorm:"uniqueIndex;size:255" json:"email"`
	Phone          string         `gorm:"uniqueIndex;size:20" json:"phone,omitempty"`
	Username       string         `gorm:"uniqueIndex;size:100" json:"username"`
	PasswordHash   string         `gorm:"size:255" json:"-"`
	FirstName      string         `gorm:"size:100" json:"firstName"`
	LastName       string         `gorm:"size:100" json:"lastName"`
	Avatar         string         `gorm:"size:500" json:"avatar,omitempty"`
	EmailVerified  bool           `gorm:"default:false" json:"emailVerified"`
	PhoneVerified  bool           `gorm:"default:false" json:"phoneVerified"`
	IsActive       bool           `gorm:"default:true" json:"isActive"`
	IsSuperAdmin   bool           `gorm:"default:false" json:"isSuperAdmin"`
	LastLoginAt    *time.Time     `json:"lastLoginAt,omitempty"`
	LastLoginIP    string         `gorm:"size:45" json:"lastLoginIP,omitempty"`
	FailedAttempts int            `gorm:"default:0" json:"-"`
	LockedUntil    *time.Time     `json:"lockedUntil,omitempty"`
	Metadata       string         `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Tenant        *Tenant        `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
	Roles         []Role         `gorm:"many2many:user_roles;" json:"roles,omitempty"`
	Sessions      []Session      `gorm:"foreignKey:UserID" json:"-"`
	RefreshTokens []RefreshToken `gorm:"foreignKey:UserID" json:"-"`
	OAuthAccounts []OAuthAccount `gorm:"foreignKey:UserID" json:"-"`
	TenantMembers []TenantMember `gorm:"foreignKey:UserID" json:"-"`
}

func (u *User) TableName() string {
	return "users"
}

func (u *User) FullName() string {
	return u.FirstName + " " + u.LastName
}

func (u *User) IsLocked() bool {
	if u.LockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.LockedUntil)
}
