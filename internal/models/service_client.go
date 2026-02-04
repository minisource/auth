package models

import (
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ServiceClient represents a service that can authenticate via OAuth2 client credentials
// Used for service-to-service authentication (e.g., notifier calling auth, or backend calling notifier)
type ServiceClient struct {
	ID           uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	TenantID     *uuid.UUID     `gorm:"type:uuid;index" json:"tenantId,omitempty"` // nil = system-wide client
	Name         string         `gorm:"size:100;not null;index:idx_tenant_client_name,unique" json:"name"`
	ClientID     string         `gorm:"uniqueIndex;size:255;not null" json:"clientId"`
	ClientSecret string         `gorm:"size:255;not null" json:"-"` // Hashed secret
	Description  string         `gorm:"size:500" json:"description,omitempty"`
	Scopes       string         `gorm:"size:1000" json:"scopes,omitempty"` // Comma-separated scopes
	IsActive     bool           `gorm:"default:true" json:"isActive"`
	LastUsedAt   *time.Time     `json:"lastUsedAt,omitempty"`
	ExpiresAt    *time.Time     `json:"expiresAt,omitempty"` // Optional expiry
	Metadata     string         `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
	CreatedAt    time.Time      `json:"createdAt"`
	UpdatedAt    time.Time      `json:"updatedAt"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationships
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

func (s *ServiceClient) TableName() string {
	return "service_clients"
}

func (s *ServiceClient) IsExpired() bool {
	if s.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*s.ExpiresAt)
}

func (s *ServiceClient) IsValid() bool {
	return s.IsActive && !s.IsExpired()
}

// GetScopesList returns scopes as a slice
func (s *ServiceClient) GetScopesList() []string {
	if s.Scopes == "" {
		return []string{}
	}
	var scopes []string
	for _, scope := range splitAndTrim(s.Scopes, ",") {
		if scope != "" {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// HasScope checks if client has a specific scope
func (s *ServiceClient) HasScope(scope string) bool {
	for _, s := range s.GetScopesList() {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

func splitAndTrim(s, sep string) []string {
	var result []string
	for _, part := range strings.Split(s, sep) {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// Common service client names
const (
	ServiceClientNotifier = "notifier-service"
	ServiceClientAuth     = "auth-service"
	ServiceClientCMS      = "cms-service"
)

// Common scopes
const (
	ScopeAll           = "*"
	ScopeNotifications = "notifications"
	ScopeUsers         = "users"
	ScopeRoles         = "roles"
	ScopeSettings      = "settings"
)
