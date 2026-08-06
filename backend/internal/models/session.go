package models

import (
	"time"

	"github.com/google/uuid"
)

// Session represents an active user session
type Session struct {
	ID           uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID     *uuid.UUID `gorm:"type:uuid;index" json:"tenantId,omitempty"` // Tenant context for this session
	UserID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"userId"`
	AccessToken  string     `gorm:"size:500;index" json:"-"`
	RefreshToken string     `gorm:"size:500;index" json:"-"`
	UserAgent    string     `gorm:"size:500" json:"userAgent,omitempty"`
	IPAddress    string     `gorm:"size:45" json:"ipAddress,omitempty"`
	DeviceType   string     `gorm:"size:50" json:"deviceType,omitempty"`
	IsActive     bool       `gorm:"default:true;index" json:"isActive"`
	ExpiresAt    time.Time  `gorm:"index" json:"expiresAt"`
	LastActiveAt time.Time  `json:"lastActiveAt"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (s *Session) TableName() string {
	return "sessions"
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

func (s *Session) IsValid() bool {
	return s.IsActive && !s.IsExpired() && s.RevokedAt == nil
}

// RefreshToken represents a refresh token for JWT renewal
type RefreshToken struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;index;not null" json:"userId"`
	Token     string     `gorm:"uniqueIndex;size:500;not null" json:"-"`
	SessionID uuid.UUID  `gorm:"type:uuid;index" json:"sessionId"`
	ExpiresAt time.Time  `gorm:"index" json:"expiresAt"`
	IsRevoked bool       `gorm:"default:false;index" json:"isRevoked"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`

	// Relationships
	User    User    `gorm:"foreignKey:UserID" json:"-"`
	Session Session `gorm:"foreignKey:SessionID" json:"-"`
}

func (r *RefreshToken) TableName() string {
	return "refresh_tokens"
}

func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

func (r *RefreshToken) IsValid() bool {
	return !r.IsRevoked && !r.IsExpired()
}
