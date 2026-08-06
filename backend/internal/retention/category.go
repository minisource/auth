package retention

import (
	"github.com/minisource/go-common/retention"
)

// AuthCategory identifies a cleanup target within the Auth service.
type AuthCategory string

const (
	CategoryLoginLogs AuthCategory = "login_logs"
	CategorySessions  AuthCategory = "sessions"
)

// CategoryMeta describes a cleanup category for registration.
type CategoryMeta struct {
	Category        AuthCategory
	DisplayName     string
	Description     string
	TableName       string
	MinRetentionDays int // safety floor
	Protected       bool // when true, category is excluded from cleanup
}

// Registry returns the allowlist of cleanup categories for Auth.
// Any category NOT in this list is implicitly protected.
func Registry() []CategoryMeta {
	return []CategoryMeta{
		{
			Category:         CategoryLoginLogs,
			DisplayName:      "Login History",
			Description:      "Successful/failed login events, OTP verifications, OAuth logins, password resets, and security events",
			TableName:        "login_logs",
			MinRetentionDays: 7,
			Protected:        false,
		},
		{
			Category:         CategorySessions,
			DisplayName:      "Expired Sessions",
			Description:      "Only expired AND revoked sessions. Active sessions are never deleted.",
			TableName:        "sessions",
			MinRetentionDays: 30,
			Protected:        false,
		},
		// audit_logs is NOT registered — it is protected.
	}
}

// IsRegistered reports whether a category is in the allowlist.
func IsRegistered(cat string) bool {
	for _, m := range Registry() {
		if string(m.Category) == cat {
			return !m.Protected
		}
	}
	return false
}

// GetMeta returns metadata for a category, or nil if not found.
func GetMeta(cat string) *CategoryMeta {
	for _, m := range Registry() {
		if string(m.Category) == cat {
			return &m
		}
	}
	return nil
}

// String returns the category string.
func (c AuthCategory) String() string { return string(c) }

// ServiceName is the service identifier used in policies.
const ServiceName = "auth"

// ValidatePolicy performs Auth-specific validation on top of the shared policy
// validation. It checks that the category is registered, applies minimum
// retention days, and returns an error for protected categories.
func ValidatePolicy(p *retention.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Service != ServiceName {
		return retention.ErrInvalidPolicy
	}
	meta := GetMeta(p.Category)
	if meta == nil {
		return retention.ErrCategoryProtected
	}
	if meta.Protected {
		return retention.ErrCategoryProtected
	}
	if p.Strategy == retention.StrategyAge || p.Strategy == retention.StrategyHybrid {
		if p.RetentionDays < meta.MinRetentionDays && p.CutoffTimestamp == nil {
			return retention.ErrInvalidPolicy
		}
	}
	return nil
}
