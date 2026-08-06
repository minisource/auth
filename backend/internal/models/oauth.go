package models

import (
	"time"

	"github.com/google/uuid"
)

// OAuth provider types
const (
	OAuthProviderGoogle   = "google"
	OAuthProviderApple    = "apple"
	OAuthProviderGitHub   = "github"
	OAuthProviderFacebook = "facebook"
)

// OAuthAccount represents a linked OAuth account
type OAuthAccount struct {
	ID           uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID       uuid.UUID  `gorm:"type:uuid;index;not null" json:"userId"`
	Provider     string     `gorm:"size:50;index;not null" json:"provider"`
	ProviderID   string     `gorm:"size:255;index;not null" json:"providerId"`
	Email        string     `gorm:"size:255" json:"email,omitempty"`
	Name         string     `gorm:"size:200" json:"name,omitempty"`
	Avatar       string     `gorm:"size:500" json:"avatar,omitempty"`
	AccessToken  string     `gorm:"size:2000" json:"-"`
	RefreshToken string     `gorm:"size:2000" json:"-"`
	ExpiresAt    *time.Time `json:"expiresAt,omitempty"`
	Metadata     string     `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (o *OAuthAccount) TableName() string {
	return "oauth_accounts"
}

// Unique constraint on provider + providerId
func (o *OAuthAccount) UniqueKey() string {
	return o.Provider + ":" + o.ProviderID
}
