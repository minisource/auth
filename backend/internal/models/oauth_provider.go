package models

import (
	"database/sql/driver"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type OAuthProviderConfig map[string]interface{}

func (c OAuthProviderConfig) Value() (driver.Value, error) {
	if c == nil {
		return "{}", nil
	}
	return json.Marshal(c)
}

func (c *OAuthProviderConfig) Scan(value interface{}) error {
	if value == nil {
		*c = OAuthProviderConfig{}
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return json.Unmarshal([]byte(value.(string)), c)
	}
	return json.Unmarshal(bytes, c)
}

type OAuthProvider struct {
	ID               uuid.UUID          `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID         *uuid.UUID         `gorm:"type:uuid;index" json:"tenantId,omitempty"`
	Name             string             `gorm:"size:100;not null" json:"name"`
	Type             string             `gorm:"size:50;not null" json:"type"`
	ClientID         string             `gorm:"size:500;not null" json:"clientId"`
	ClientSecret     string             `gorm:"size:2000;not null" json:"clientSecret"`
	RedirectURL      string             `gorm:"size:500" json:"redirectUrl,omitempty"`
	Scopes           string             `gorm:"type:text" json:"scopes,omitempty"`
	AuthURL          string             `gorm:"size:500" json:"authUrl,omitempty"`
	TokenURL         string             `gorm:"size:500" json:"tokenUrl,omitempty"`
	UserInfoURL      string             `gorm:"size:500" json:"userInfoUrl,omitempty"`
	IsEnabled        bool               `gorm:"default:true" json:"isEnabled"`
	IsDefault        bool               `gorm:"default:false" json:"isDefault"`
	Config           OAuthProviderConfig `gorm:"type:jsonb;default:'{}'" json:"config"`
	TotalLogins      int64              `gorm:"default:0" json:"totalLogins"`
	SuccessfulLogins int64              `gorm:"default:0" json:"successfulLogins"`
	FailedLogins     int64              `gorm:"default:0" json:"failedLogins"`
	LastUsedAt       *time.Time         `json:"lastUsedAt,omitempty"`
	CreatedAt        time.Time          `json:"createdAt"`
	UpdatedAt        time.Time          `json:"updatedAt"`

	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

func (OAuthProvider) TableName() string {
	return "oauth_providers"
}
