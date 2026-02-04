package service

import (
	"errors"

	"github.com/minisource/go-common/service_errors"
)

// Auth-specific error codes
const (
	ErrCodeTokenRequired        = "token_required"
	ErrCodeTokenExpired         = "token_expired"
	ErrCodeTokenInvalid         = "token_invalid"
	ErrCodeUserNotFound         = "user_not_found"
	ErrCodeUserDisabled         = "user_disabled"
	ErrCodeUserLocked           = "user_locked"
	ErrCodeInvalidCredentials   = "invalid_credentials"
	ErrCodeEmailExists          = "email_exists"
	ErrCodePhoneExists          = "phone_exists"
	ErrCodeUsernameExists       = "username_exists"
	ErrCodeOTPExpired           = "otp_expired"
	ErrCodeOTPInvalid           = "otp_not_valid"
	ErrCodeOTPMaxAttempts       = "otp_max_attempts"
	ErrCodeOTPStillValid        = "otp_still_valid"
	ErrCodeSessionNotFound      = "session_not_found"
	ErrCodeSessionExpired       = "session_expired"
	ErrCodeRefreshTokenInvalid  = "refresh_token_invalid"
	ErrCodePasswordTooWeak      = "password_too_weak"
	ErrCodePasswordMismatch     = "password_mismatch"
	ErrCodePermissionDenied     = "permission_denied"
	ErrCodeRoleNotFound         = "role_not_found"
	ErrCodeRoleExists           = "role_exists"
	ErrCodePermissionNotFound   = "permission_not_found"
	ErrCodePermissionExists     = "permission_exists"
	ErrCodeOAuthFailed          = "oauth_failed"
	ErrCodeOAuthNotConfigured   = "oauth_not_configured"
	ErrCodeOAuthUnlinkFailed    = "oauth_unlink_failed"
	ErrCodeRegistrationDisabled = "registration_disabled"
	ErrCodeSystemRole           = "cannot_delete_system_role"
	ErrCodeServiceClientExists  = "service_client_exists"
	ErrCodeNotifierUnavailable  = "notifier_service_unavailable"
)

// Sentinel errors
var (
	ErrTokenRequired          = errors.New("authentication token is required")
	ErrTokenExpired           = errors.New("authentication token has expired")
	ErrTokenInvalid           = errors.New("authentication token is invalid")
	ErrUserNotFound           = errors.New("user not found")
	ErrUserDisabled           = errors.New("user account is disabled")
	ErrUserLocked             = errors.New("user account is locked")
	ErrInvalidCredentials     = errors.New("invalid email or password")
	ErrEmailExists            = errors.New("email already exists")
	ErrPhoneExists            = errors.New("phone number already exists")
	ErrUsernameExists         = errors.New("username already exists")
	ErrOTPExpired             = errors.New("OTP has expired")
	ErrOTPInvalid             = errors.New("OTP is invalid")
	ErrOTPMaxAttempts         = errors.New("maximum OTP attempts exceeded")
	ErrOTPStillValid          = errors.New("previous OTP is still valid, please wait before requesting a new one")
	ErrSessionNotFound        = errors.New("session not found")
	ErrSessionExpired         = errors.New("session has expired")
	ErrRefreshTokenInvalid    = errors.New("refresh token is invalid")
	ErrPasswordTooWeak        = errors.New("password does not meet requirements")
	ErrPasswordMismatch       = errors.New("passwords do not match")
	ErrPermissionDenied       = errors.New("permission denied")
	ErrRoleNotFound           = errors.New("role not found")
	ErrRoleExists             = errors.New("role already exists")
	ErrPermissionNotFound     = errors.New("permission not found")
	ErrPermissionExists       = errors.New("permission already exists")
	ErrOAuthFailed            = errors.New("OAuth authentication failed")
	ErrOAuthNotConfigured     = errors.New("OAuth is not configured")
	ErrOAuthUnlinkFailed      = errors.New("cannot unlink OAuth account")
	ErrRegistrationDisabled   = errors.New("registration is disabled")
	ErrCannotDeleteSystemRole = errors.New("cannot delete system role")
	ErrServiceClientExists    = errors.New("service client already exists")
)

// Error constructors for service errors with i18n support

func NewTokenRequiredError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeTokenRequired, "Authentication token is required", "")
}

func NewTokenExpiredError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeTokenExpired, "Authentication token has expired", "")
}

func NewTokenInvalidError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeTokenInvalid, "Authentication token is invalid", "")
}

func NewUserNotFoundError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeUserNotFound, "User not found", "")
}

func NewUserDisabledError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeUserDisabled, "User account is disabled", "")
}

func NewUserLockedError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeUserLocked, "User account is temporarily locked", "")
}

func NewInvalidCredentialsError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeInvalidCredentials, "Invalid email or password", "")
}

func NewEmailExistsError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeEmailExists, "Email address is already registered", "")
}

func NewPhoneExistsError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodePhoneExists, "Phone number is already registered", "")
}

func NewUsernameExistsError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeUsernameExists, "Username is already taken", "")
}

func NewOTPExpiredError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeOTPExpired, "OTP has expired", "")
}

func NewOTPInvalidError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeOTPInvalid, "OTP is invalid", "")
}

func NewOTPMaxAttemptsError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeOTPMaxAttempts, "Maximum OTP attempts exceeded", "")
}

func NewOTPStillValidError(remainingSeconds int64) *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeOTPStillValid, "Previous OTP is still valid, please wait before requesting a new one", "").
		WithDetails(map[string]interface{}{"remainingSeconds": remainingSeconds})
}

func NewSessionNotFoundError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeSessionNotFound, "Session not found", "")
}

func NewRefreshTokenInvalidError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeRefreshTokenInvalid, "Refresh token is invalid or expired", "")
}

func NewPasswordTooWeakError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodePasswordTooWeak, "Password does not meet security requirements", "")
}

func NewPermissionDeniedError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodePermissionDenied, "You don't have permission to perform this action", "")
}

func NewRoleNotFoundError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeRoleNotFound, "Role not found", "")
}

func NewOAuthFailedError(provider string) *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeOAuthFailed, "OAuth authentication failed", "").
		WithDetails(map[string]interface{}{"provider": provider})
}

func NewRegistrationDisabledError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeRegistrationDisabled, "User registration is currently disabled", "")
}

func NewNotifierUnavailableError() *service_errors.ServiceError {
	return service_errors.NewServiceError(ErrCodeNotifierUnavailable, "Notification service is temporarily unavailable, please try again later", "")
}
