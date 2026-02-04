package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusInactive  TenantStatus = "inactive"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusTrial     TenantStatus = "trial"
)

// TenantSettings represents tenant-specific configuration
type TenantSettings struct {
	AllowUserRegistration bool     `json:"allowUserRegistration"`
	RequireEmailVerified  bool     `json:"requireEmailVerified"`
	RequirePhoneVerified  bool     `json:"requirePhoneVerified"`
	AllowedAuthMethods    []string `json:"allowedAuthMethods"`
	SessionTimeout        int      `json:"sessionTimeout"` // hours
	MaxSessionsPerUser    int      `json:"maxSessionsPerUser"`
	CustomBranding        bool     `json:"customBranding"`
	PasswordPolicy        string   `json:"passwordPolicy,omitempty"`
}

// Value implements driver.Valuer for database storage
func (s TenantSettings) Value() (driver.Value, error) {
	return json.Marshal(s)
}

// Scan implements sql.Scanner for database retrieval
func (s *TenantSettings) Scan(value interface{}) error {
	if value == nil {
		*s = TenantSettings{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), s)
	}
	return json.Unmarshal(bytes, s)
}

// TenantLimits represents usage limits for a tenant
type TenantLimits struct {
	MaxUsers          int `json:"maxUsers"`
	MaxRoles          int `json:"maxRoles"`
	MaxServiceClients int `json:"maxServiceClients"`
	MaxMembersPerRole int `json:"maxMembersPerRole"`
	MaxAPIRequests    int `json:"maxApiRequests"` // Per month
	MaxStorageMB      int `json:"maxStorageMB"`   // Storage limit in MB
}

// Value implements driver.Valuer for database storage
func (l TenantLimits) Value() (driver.Value, error) {
	return json.Marshal(l)
}

// Scan implements sql.Scanner for database retrieval
func (l *TenantLimits) Scan(value interface{}) error {
	if value == nil {
		*l = TenantLimits{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), l)
	}
	return json.Unmarshal(bytes, l)
}

// Tenant represents a tenant/organization in a multi-tenant system
type Tenant struct {
	ID          uuid.UUID    `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string       `gorm:"size:255;not null" json:"name"`
	Slug        string       `gorm:"uniqueIndex;size:100;not null" json:"slug"` // Unique identifier for URLs/subdomains
	DisplayName string       `gorm:"size:255" json:"displayName"`
	Description string       `gorm:"size:1000" json:"description,omitempty"`
	Logo        string       `gorm:"size:500" json:"logo,omitempty"`
	Domain      string       `gorm:"size:255;index" json:"domain,omitempty"` // Custom domain if any
	Status      TenantStatus `gorm:"type:varchar(20);default:'active'" json:"status"`
	IsDefault   bool         `gorm:"default:false" json:"isDefault"` // Default tenant for the system

	// JSONB fields with custom types
	Settings TenantSettings `gorm:"type:jsonb;default:'{}'" json:"settings"`
	Limits   TenantLimits   `gorm:"type:jsonb;default:'{}'" json:"limits"`
	Metadata string         `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`

	// Subscription/Plan info
	Plan         string     `gorm:"size:50;default:'free'" json:"plan"`
	BillingCycle string     `gorm:"size:20;default:'monthly'" json:"billingCycle"`
	PlanID       *uuid.UUID `gorm:"type:uuid;index" json:"planId,omitempty"`
	PlanName     string     `gorm:"size:100" json:"planName,omitempty"`
	TrialEndsAt  *time.Time `json:"trialEndsAt,omitempty"`

	// Contact info
	ContactEmail string `gorm:"size:255" json:"contactEmail,omitempty"`
	ContactPhone string `gorm:"size:20" json:"contactPhone,omitempty"`

	// Billing address
	BillingAddress string `gorm:"type:jsonb" json:"billingAddress,omitempty"`

	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Users          []User          `gorm:"foreignKey:TenantID" json:"-"`
	Roles          []Role          `gorm:"foreignKey:TenantID" json:"-"`
	ServiceClients []ServiceClient `gorm:"foreignKey:TenantID" json:"-"`
}

func (t *Tenant) TableName() string {
	return "tenants"
}

// IsActive checks if tenant is in active status
func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive || t.Status == TenantStatusTrial
}

// TenantMember represents a user's membership in a tenant
type TenantMember struct {
	TenantID  uuid.UUID  `gorm:"type:uuid;primaryKey" json:"tenantId"`
	UserID    uuid.UUID  `gorm:"type:uuid;primaryKey" json:"userId"`
	RoleID    *uuid.UUID `gorm:"type:uuid;index" json:"roleId,omitempty"` // Role within this tenant
	IsOwner   bool       `gorm:"default:false" json:"isOwner"`            // Is tenant owner/admin
	IsDefault bool       `gorm:"default:false" json:"isDefault"`          // User's default tenant
	JoinedAt  time.Time  `gorm:"autoCreateTime" json:"joinedAt"`
	InvitedBy *uuid.UUID `gorm:"type:uuid" json:"invitedBy,omitempty"`

	// Relationships
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
	User   *User   `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Role   *Role   `gorm:"foreignKey:RoleID" json:"role,omitempty"`
}

func (TenantMember) TableName() string {
	return "tenant_members"
}

// TenantInvitation represents a pending invitation to join a tenant
type TenantInvitation struct {
	ID         uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID   uuid.UUID      `gorm:"type:uuid;not null;index" json:"tenantId"`
	Email      string         `gorm:"size:255;not null;index" json:"email"`
	RoleID     *uuid.UUID     `gorm:"type:uuid" json:"roleId,omitempty"`
	Token      string         `gorm:"size:255;uniqueIndex" json:"-"`
	InvitedBy  uuid.UUID      `gorm:"type:uuid;not null" json:"invitedBy"`
	ExpiresAt  time.Time      `gorm:"not null" json:"expiresAt"`
	AcceptedAt *time.Time     `json:"acceptedAt,omitempty"`
	CreatedAt  time.Time      `json:"createdAt"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

func (TenantInvitation) TableName() string {
	return "tenant_invitations"
}
