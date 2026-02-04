package models

import (
	"time"

	"github.com/google/uuid"
)

// LoginLog action types
const (
	LoginActionLogin           = "login"
	LoginActionLogout          = "logout"
	LoginActionLoginFailed     = "login_failed"
	LoginActionPasswordReset   = "password_reset"
	LoginActionPasswordChange  = "password_change"
	LoginActionTokenRefresh    = "token_refresh"
	LoginActionOTPVerify       = "otp_verify"
	LoginActionOAuthLogin      = "oauth_login"
	LoginActionAccountLocked   = "account_locked"
	LoginActionAccountUnlocked = "account_unlocked"
)

// LoginLog represents a login/logout audit log entry
type LoginLog struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;index" json:"userId"`
	SessionID uuid.UUID `gorm:"type:uuid;index" json:"sessionId,omitempty"`
	Action    string    `gorm:"size:50;index;not null" json:"action"`
	IPAddress string    `gorm:"size:45;index" json:"ipAddress,omitempty"`
	UserAgent string    `gorm:"size:500" json:"userAgent,omitempty"`
	Location  string    `gorm:"size:200" json:"location,omitempty"`
	Device    string    `gorm:"size:200" json:"device,omitempty"`
	Success   bool      `gorm:"default:true;index" json:"success"`
	ErrorMsg  string    `gorm:"size:500" json:"errorMsg,omitempty"`
	Metadata  string    `gorm:"type:jsonb;default:'{}'" json:"metadata,omitempty"`
	CreatedAt time.Time `gorm:"index" json:"createdAt"`

	// Relationships
	User    User    `gorm:"foreignKey:UserID" json:"-"`
	Session Session `gorm:"foreignKey:SessionID" json:"-"`
}

func (l *LoginLog) TableName() string {
	return "login_logs"
}
