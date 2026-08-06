package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Passkey represents a WebAuthn passkey (public key credential) bound to a user.
// The full go-webauthn Credential is stored as JSON so sign-count updates and
// authenticator metadata survive restarts.
type Passkey struct {
	ID             uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID         uuid.UUID      `gorm:"type:uuid;index;not null" json:"userId"`
	Name           string         `gorm:"size:100" json:"name"`
	CredentialID   string         `gorm:"size:1024;index;not null" json:"credentialId"` // base64url credential ID
	CredentialJSON string         `gorm:"type:jsonb" json:"-"`                          // full webauthn.Credential
	AAGUID         string         `gorm:"size:64" json:"aaguid,omitempty"`
	SignCount      uint32         `json:"-"`
	BackupEligible bool           `json:"backupEligible"`
	BackupState    bool           `json:"backupState"`
	LastUsedAt     *time.Time     `json:"lastUsedAt,omitempty"`
	CreatedAt      time.Time      `json:"createdAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

func (Passkey) TableName() string {
	return "passkeys"
}
