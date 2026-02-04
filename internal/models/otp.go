package models

import (
	"time"

	"github.com/google/uuid"
)

// OTP types
const (
	OTPTypeEmailVerification = "email_verification"
	OTPTypePhoneVerification = "phone_verification"
	OTPTypePasswordReset     = "password_reset"
	OTPTypeLogin             = "login"
)

// OTP represents a one-time password
type OTP struct {
	ID        uuid.UUID  `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID  `gorm:"type:uuid;index" json:"userId"`
	Code      string     `gorm:"size:10;not null" json:"code"` // Changed from json:"-" to allow Redis storage
	Type      string     `gorm:"size:50;index;not null" json:"type"`
	Target    string     `gorm:"size:255;index;not null" json:"target"` // email or phone
	Attempts  int        `gorm:"default:0" json:"attempts"`
	IsUsed    bool       `gorm:"default:false;index" json:"isUsed"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
	ExpiresAt time.Time  `gorm:"index" json:"expiresAt"`
	CreatedAt time.Time  `json:"createdAt"`

	// Relationships
	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (o *OTP) TableName() string {
	return "otps"
}

func (o *OTP) IsExpired() bool {
	return time.Now().After(o.ExpiresAt)
}

func (o *OTP) IsValid(code string, maxAttempts int) bool {
	return !o.IsUsed && !o.IsExpired() && o.Attempts < maxAttempts && o.Code == code
}

func (o *OTP) CanRetry(maxAttempts int) bool {
	return !o.IsUsed && !o.IsExpired() && o.Attempts < maxAttempts
}
