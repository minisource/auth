package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Setting represents a configuration setting stored in the database
type Setting struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Key         string         `gorm:"uniqueIndex;size:255;not null" json:"key"`
	Value       string         `gorm:"type:text" json:"value"`
	Type        string         `gorm:"size:50;default:'string'" json:"type"` // string, int, bool, json
	Category    string         `gorm:"size:100;index" json:"category"`
	Description string         `gorm:"size:500" json:"description,omitempty"`
	IsPublic    bool           `gorm:"default:false" json:"isPublic"`
	CreatedAt   time.Time      `json:"createdAt"`
	UpdatedAt   time.Time      `json:"updatedAt"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

func (s *Setting) TableName() string {
	return "settings"
}

// Common setting keys
const (
	SettingKeyMaxLoginAttempts   = "max_login_attempts"
	SettingKeyLockDuration       = "lock_duration_minutes"
	SettingKeySessionTimeout     = "session_timeout_minutes"
	SettingKeyPasswordPolicy     = "password_policy"
	SettingKeyOTPLength          = "otp_length"
	SettingKeyOTPExpiry          = "otp_expiry_minutes"
	SettingKeyAllowRegistration  = "allow_registration"
	SettingKeyRequireEmailVerify = "require_email_verification"
	SettingKeyRequirePhoneVerify = "require_phone_verification"
	SettingKeyEnableGoogleLogin  = "enable_google_login"
	SettingKeyEnableOTPLogin     = "enable_otp_login"
	SettingKeyMaintenanceMode    = "maintenance_mode"
)

// Setting categories
const (
	SettingCategorySecurity     = "security"
	SettingCategoryAuth         = "auth"
	SettingCategoryNotification = "notification"
	SettingCategoryGeneral      = "general"
)
