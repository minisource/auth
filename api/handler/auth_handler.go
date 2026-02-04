package handler

import (
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/i18n"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
	"github.com/minisource/go-common/service_errors"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService  *service.AuthService
	oauthService *service.OAuthService
	logger       logging.Logger
}

func NewAuthHandler(
	authService *service.AuthService,
	oauthService *service.OAuthService,
	logger logging.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		oauthService: oauthService,
		logger:       logger,
	}
}

// Login godoc
// @Summary User login
// @Description Authenticate user with email and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login credentials"
// @Success 200 {object} dto.AuthResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	var req dto.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	authReq := &service.LoginRequest{
		Email:     req.Email,
		Password:  req.Password,
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
	}

	resp, err := h.authService.Login(c.Context(), authReq)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, resp)
}

// Register godoc
// @Summary User registration
// @Description Register a new user account
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.RegisterRequest true "Registration data"
// @Success 201 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *fiber.Ctx) error {
	var req dto.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	regReq := &service.RegisterRequest{
		Email:     req.Email,
		Password:  req.Password,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Phone:     req.Phone,
	}

	_, err := h.authService.Register(c.Context(), regReq)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, dto.MessageResponse{
		Message: i18n.T(c.Context(), "auth.register_success") + " " + i18n.T(c.Context(), "auth.verification_email_sent"),
	})
}

// SendOTP godoc
// @Summary Send OTP
// @Description Send OTP to phone or email. Auto-registers user if phone doesn't exist.
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.SendOTPRequest true "OTP request"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /auth/otp/send [post]
func (h *AuthHandler) SendOTP(c *fiber.Ctx) error {
	var req dto.SendOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	// Default type to "login" if not provided
	if req.Type == "" {
		req.Type = "login"
	}

	h.logger.Debug(logging.Validation, logging.Api, "SendOTP request received", map[logging.ExtraKey]interface{}{
		"phone": req.Phone,
		"email": req.Email,
		"type":  req.Type,
	})

	otpReq := &service.SendOTPRequest{
		Phone:     req.Phone,
		Email:     req.Email,
		Type:      req.Type,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}

	otpResp, err := h.authService.SendOTP(c.Context(), otpReq)
	if err != nil {
		// Log detailed error information
		h.logger.Error(logging.General, logging.Api, "SendOTP failed with error", map[logging.ExtraKey]interface{}{
			"error":     err.Error(),
			"errorType": fmt.Sprintf("%T", err),
			"phone":     req.Phone,
			"email":     req.Email,
			"type":      req.Type,
		})
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, map[string]interface{}{
		"message":   i18n.T(c.Context(), "auth.otp_sent"),
		"expiresAt": otpResp.ExpiresAt,
		"expiresIn": otpResp.ExpiresIn,
	})
}

// VerifyOTP godoc
// @Summary Verify OTP and login
// @Description Verify OTP and create session
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.VerifyOTPRequest true "OTP verification"
// @Success 200 {object} dto.AuthResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/otp/verify [post]
func (h *AuthHandler) VerifyOTP(c *fiber.Ctx) error {
	var req dto.VerifyOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	resp, err := h.authService.VerifyOTPAndLogin(
		c.Context(),
		req.Target,
		req.Code,
		req.Type,
		c.IP(),
		c.Get("User-Agent"),
	)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, resp)
}

// RefreshToken godoc
// @Summary Refresh tokens
// @Description Refresh access and refresh tokens
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} dto.AuthResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req dto.RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	resp, err := h.authService.RefreshTokens(c.Context(), req.RefreshToken)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, resp)
}

// Logout godoc
// @Summary Logout
// @Description Logout and revoke session
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.LogoutRequest true "Logout options"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	var req dto.LogoutRequest
	c.BodyParser(&req) // Optional body

	token := getTokenFromHeader(c)
	if token == "" {
		return response.Unauthorized(c, i18n.T(c.Context(), "errors.token_required"))
	}

	if err := h.authService.Logout(c.Context(), token, req.RevokeAll); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, dto.MessageResponse{
		Message: i18n.T(c.Context(), "auth.logout_success"),
	})
}

// GetGoogleAuthURL godoc
// @Summary Get Google OAuth URL
// @Description Get Google OAuth authorization URL
// @Tags Auth
// @Produce json
// @Success 200 {object} dto.GoogleAuthURLResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /auth/google [get]
func (h *AuthHandler) GetGoogleAuthURL(c *fiber.Ctx) error {
	state := c.Query("state", "")
	if state == "" {
		// Generate random state
		state, _ = service.GenerateSecureToken(16)
	}

	url, err := h.oauthService.GetGoogleAuthURL(state)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.GoogleAuthURLResponse{
		URL: url,
	})
}

// GoogleCallback godoc
// @Summary Google OAuth callback
// @Description Handle Google OAuth callback
// @Tags Auth
// @Accept json
// @Produce json
// @Param code query string true "Authorization code"
// @Success 200 {object} dto.AuthResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /auth/google/callback [get]
func (h *AuthHandler) GoogleCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		return response.BadRequest(c, "INVALID_REQUEST", "Authorization code required")
	}

	resp, err := h.oauthService.HandleGoogleCallback(
		c.Context(),
		code,
		c.IP(),
		c.Get("User-Agent"),
	)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(resp)
}

// Helper functions

func getTokenFromHeader(c *fiber.Ctx) string {
	auth := c.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

func handleAuthError(c *fiber.Ctx, err error, logger logging.Logger) error {
	ctx := c.Context()

	// Check if it's a ServiceError from go-common
	var serviceErr *service_errors.ServiceError
	if errors.As(err, &serviceErr) {
		message := i18n.T(ctx, "errors."+serviceErr.Code)
		if message == "errors."+serviceErr.Code {
			// Translation not found, use the error message
			message = serviceErr.EndUserMessage
		}

		switch serviceErr.Code {
		case service.ErrCodeNotifierUnavailable:
			return response.ServiceUnavailable(c, message)
		case service.ErrCodeInvalidCredentials, service.ErrCodeOTPInvalid, service.ErrCodeOTPExpired, service.ErrCodeRefreshTokenInvalid:
			return response.Unauthorized(c, message)
		case service.ErrCodeUserDisabled, service.ErrCodeUserLocked, service.ErrCodeRegistrationDisabled, service.ErrCodePermissionDenied:
			return response.Forbidden(c, message)
		case service.ErrCodeEmailExists, service.ErrCodePhoneExists, service.ErrCodeUsernameExists:
			return response.Conflict(c, message)
		case service.ErrCodeUserNotFound, service.ErrCodeRoleNotFound, service.ErrCodePermissionNotFound:
			return response.NotFound(c, message)
		case service.ErrCodeOTPStillValid:
			// Return 429 Too Many Requests with remaining time
			return c.Status(429).JSON(fiber.Map{
				"success": false,
				"error": fiber.Map{
					"code":    serviceErr.Code,
					"message": message,
					"details": serviceErr.Details,
				},
			})
		default:
			return response.BadRequest(c, serviceErr.Code, message)
		}
	}

	// Handle legacy errors
	switch err {
	case service.ErrInvalidCredentials:
		return response.Unauthorized(c, i18n.T(ctx, "errors.invalid_credentials"))
	case service.ErrUserDisabled:
		return response.Forbidden(c, i18n.T(ctx, "errors.user_disabled"))
	case service.ErrUserLocked:
		return response.Forbidden(c, i18n.T(ctx, "errors.user_locked"))
	case service.ErrEmailExists:
		return response.Conflict(c, i18n.T(ctx, "errors.email_exists"))
	case service.ErrPhoneExists:
		return response.Conflict(c, i18n.T(ctx, "errors.phone_exists"))
	case service.ErrUsernameExists:
		return response.Conflict(c, i18n.T(ctx, "errors.username_exists"))
	case service.ErrUserNotFound:
		return response.NotFound(c, i18n.T(ctx, "errors.user_not_found"))
	case service.ErrRoleNotFound:
		return response.NotFound(c, i18n.T(ctx, "errors.role_not_found"))
	case service.ErrPermissionNotFound:
		return response.NotFound(c, i18n.T(ctx, "errors.permission_not_found"))
	case service.ErrOTPInvalid:
		return response.Unauthorized(c, i18n.T(ctx, "errors.otp_invalid"))
	case service.ErrOTPExpired:
		return response.Unauthorized(c, i18n.T(ctx, "errors.otp_expired"))
	case service.ErrRefreshTokenInvalid:
		return response.Unauthorized(c, i18n.T(ctx, "errors.refresh_token_invalid"))
	case service.ErrRegistrationDisabled:
		return response.Forbidden(c, i18n.T(ctx, "errors.registration_disabled"))
	default:
		// Log unhandled errors for debugging
		logger.Error(logging.General, logging.Api, "Unhandled error in auth handler", map[logging.ExtraKey]interface{}{
			"error":     err.Error(),
			"errorType": fmt.Sprintf("%T", err),
		})
		return response.InternalError(c, i18n.T(ctx, "errors.internal_error"))
	}
}

// ForgotPassword godoc
// @Summary Request password reset
// @Description Send OTP to email/phone for password reset
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.ForgotPasswordRequest true "Email or phone"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *fiber.Ctx) error {
	var req dto.ForgotPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	// Use SendOTP with password_reset type
	otpReq := &service.SendOTPRequest{
		Email: req.Email,
		Phone: req.Phone,
		Type:  "password_reset",
	}

	if _, err := h.authService.SendOTP(c.Context(), otpReq); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, dto.MessageResponse{
		Message: i18n.T(c.Context(), "auth.password_reset_sent"),
	})
}

// ResetPassword godoc
// @Summary Reset password with OTP
// @Description Verify OTP and set new password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.ResetPasswordRequest true "OTP and new password"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *fiber.Ctx) error {
	var req dto.ResetPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	if err := h.authService.ResetPassword(c.Context(), req.Target, req.Code, req.NewPassword); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, dto.MessageResponse{
		Message: i18n.T(c.Context(), "auth.password_changed"),
	})
}

// VerifyEmail godoc
// @Summary Verify email address
// @Description Verify email using OTP code
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.VerifyOTPRequest true "OTP verification"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /auth/verify-email [post]
func (h *AuthHandler) VerifyEmail(c *fiber.Ctx) error {
	var req dto.VerifyOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	// Verify OTP and mark email as verified
	if err := h.authService.VerifyEmailOrPhone(c.Context(), req.Target, req.Code, "email_verification"); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, dto.MessageResponse{
		Message: i18n.T(c.Context(), "auth.email_verified"),
	})
}

// ResendVerification godoc
// @Summary Resend verification code
// @Description Resend OTP for email or phone verification
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dto.SendOTPRequest true "Target for verification"
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /auth/resend-verification [post]
func (h *AuthHandler) ResendVerification(c *fiber.Ctx) error {
	var req dto.SendOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", i18n.T(c.Context(), "errors.invalid_request"))
	}

	// Determine verification type based on input
	otpType := req.Type
	if otpType == "" {
		if req.Email != "" {
			otpType = "email_verification"
		} else if req.Phone != "" {
			otpType = "phone_verification"
		}
	}

	otpReq := &service.SendOTPRequest{
		Email: req.Email,
		Phone: req.Phone,
		Type:  otpType,
	}

	if _, err := h.authService.SendOTP(c.Context(), otpReq); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, dto.MessageResponse{
		Message: i18n.T(c.Context(), "auth.otp_sent"),
	})
}
