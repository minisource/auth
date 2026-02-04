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
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
	Avatar    string `json:"avatar,omitempty"`
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

type MessageResponse struct {
	Message string `json:"message"`
}

type ErrorResponse struct {
	Error   string `json:"error"`
	Code    int    `json:"code"`
	Message string `json:"message"`
}
