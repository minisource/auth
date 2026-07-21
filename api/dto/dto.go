package dto

import "github.com/google/uuid"

// === Auth DTOs ===

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Phone     string `json:"phone,omitempty"`
}

type SendOTPRequest struct {
	Phone     string `json:"phone,omitempty"`
	Email     string `json:"email,omitempty"`
	Type      string `json:"type,omitempty" validate:"omitempty,oneof=login email_verification phone_verification password_reset"` // Optional, defaults to "login"
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

type VerifyOTPRequest struct {
	Target string `json:"target" validate:"required"` // Phone or Email
	Code   string `json:"code" validate:"required,len=6"`
	Type   string `json:"type" validate:"required,oneof=login email_verification phone_verification password_reset"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type LogoutRequest struct {
	RevokeAll bool `json:"revokeAll,omitempty"`
}

type GoogleAuthRequest struct {
	Code string `json:"code" validate:"required"`
}

type ResetPasswordRequest struct {
	Target      string `json:"target" validate:"required"`     // Email or Phone
	Code        string `json:"code" validate:"required,len=6"` // OTP code
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

// === User DTOs ===

type UpdateProfileRequest struct {
	FirstName string  `json:"firstName,omitempty"`
	LastName  string  `json:"lastName,omitempty"`
	Avatar    string  `json:"avatar,omitempty"`
	Birthday  *string `json:"birthday,omitempty"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=8"`
}

type SetPasswordRequest struct {
	Password string `json:"password" validate:"required,min=8"`
}

// === Admin User DTOs ===

type CreateUserRequest struct {
	Email     string      `json:"email" validate:"required,email"`
	Password  string      `json:"password" validate:"required,min=8"`
	Username  string      `json:"username,omitempty"`
	FirstName string      `json:"firstName,omitempty"`
	LastName  string      `json:"lastName,omitempty"`
	Phone     string      `json:"phone,omitempty"`
	RoleIDs   []uuid.UUID `json:"roleIds,omitempty"`
	IsActive  bool        `json:"isActive"`
}

type UpdateUserRequest struct {
	FirstName     string      `json:"firstName,omitempty"`
	LastName      string      `json:"lastName,omitempty"`
	Phone         string      `json:"phone,omitempty"`
	IsActive      bool        `json:"isActive"`
	EmailVerified bool        `json:"emailVerified"`
	PhoneVerified bool        `json:"phoneVerified"`
	RoleIDs       []uuid.UUID `json:"roleIds,omitempty"`
}

type ListUsersRequest struct {
	Page     int       `query:"page"`
	PageSize int       `query:"pageSize"`
	Search   string    `query:"search"`
	RoleID   uuid.UUID `query:"roleId"`
	IsActive *bool     `query:"isActive"`
}

// === Role DTOs ===

type CreateRoleRequest struct {
	Name          string      `json:"name" validate:"required"`
	Description   string      `json:"description,omitempty"`
	PermissionIDs []uuid.UUID `json:"permissionIds,omitempty"`
}

type UpdateRoleRequest struct {
	Name          string      `json:"name" validate:"required"`
	Description   string      `json:"description,omitempty"`
	PermissionIDs []uuid.UUID `json:"permissionIds,omitempty"`
}

// === Permission DTOs ===

type CreatePermissionRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description,omitempty"`
	Resource    string `json:"resource" validate:"required"`
	Action      string `json:"action" validate:"required"`
}

type UpdatePermissionRequest struct {
	Name        string `json:"name" validate:"required"`
	Description string `json:"description,omitempty"`
	Resource    string `json:"resource" validate:"required"`
	Action      string `json:"action" validate:"required"`
}

// === Service Auth DTOs ===

type ServiceAuthRequest struct {
	ClientID     string `json:"clientId" validate:"required"`
	ClientSecret string `json:"clientSecret" validate:"required"`
}

type CreateServiceClientRequest struct {
	Name        string   `json:"name" validate:"required"`
	Scopes      []string `json:"scopes,omitempty"`
	Description string   `json:"description,omitempty"`
}

// === Response DTOs ===

type AuthResponse struct {
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken"`
	ExpiresAt    string    `json:"expiresAt"`
	TokenType    string    `json:"tokenType"`
	User         *UserInfo `json:"user,omitempty"`
}

type UserInfo struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	Username      string   `json:"username"`
	FirstName     string   `json:"firstName"`
	LastName      string   `json:"lastName"`
	Phone         string   `json:"phone,omitempty"`
	Avatar        string   `json:"avatar,omitempty"`
	Birthday      *string  `json:"birthday,omitempty"`
	EmailVerified bool     `json:"emailVerified"`
	PhoneVerified bool     `json:"phoneVerified"`
	Roles         []string `json:"roles"`
}

type ServiceAuthResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	TokenType   string `json:"tokenType"`
}

type GoogleAuthURLResponse struct {
	URL string `json:"url"`
}

// GoogleMobileLoginRequest is the request from mobile app after Google Sign-In.
// The mobile app obtains idToken + accessToken via the google_sign_in Flutter package.
type GoogleMobileLoginRequest struct {
	IDToken      string `json:"idToken" validate:"required"`
	AccessToken  string `json:"accessToken,omitempty"`
	DisplayName  string `json:"displayName,omitempty"`
	Email        string `json:"email,omitempty"`
	PhotoURL     string `json:"photoUrl,omitempty"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// === Userinfo DTOs ===

type UserinfoResponse struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Phone         string   `json:"phone,omitempty"`
	PhoneVerified bool     `json:"phone_verified"`
	Name          string   `json:"name"`
	GivenName     string   `json:"given_name"`
	FamilyName    string   `json:"family_name"`
	Picture       string   `json:"picture,omitempty"`
	Birthday      *string  `json:"birthday,omitempty"`
	Roles         []string `json:"roles"`
	Permissions   []string `json:"permissions"`
	TenantID      string   `json:"tenant_id,omitempty"`
	IsSuperAdmin  bool     `json:"is_super_admin"`
}

// === Introspect DTOs ===

type IntrospectRequest struct {
	Token         string `json:"token" validate:"required"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

type IntrospectResponse struct {
	Active        bool     `json:"active"`
	Sub           string   `json:"sub,omitempty"`
	Email         string   `json:"email,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	TenantID      string   `json:"tenant_id,omitempty"`
	IsSuperAdmin  bool     `json:"is_super_admin,omitempty"`
	Issuer        string   `json:"iss,omitempty"`
	Audience      []string `json:"aud,omitempty"`
	ExpiresAt     int64    `json:"exp,omitempty"`
	IssuedAt      int64    `json:"iat,omitempty"`
	TokenType     string   `json:"token_type,omitempty"`
	SessionID     string   `json:"session_id,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	ServiceName   string   `json:"service_name,omitempty"`
	Scopes        []string `json:"scopes,omitempty"`
}

// === Account Phone DTOs ===

// PhoneStartRequest is sent by an authenticated user to add a phone number.
type PhoneStartRequest struct {
	Phone string `json:"phone" validate:"required"`
}

// PhoneVerifyRequest is sent by an authenticated user to verify OTP and set phone.
type PhoneVerifyRequest struct {
	Phone string `json:"phone" validate:"required"`
	Code  string `json:"code" validate:"required,len=6"`
}
