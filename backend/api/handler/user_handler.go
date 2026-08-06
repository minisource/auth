package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// UserHandler handles user endpoints
type UserHandler struct {
	userService   *service.UserService
	oauthService  *service.OAuthService
	tenantService service.TenantService
	logger        logging.Logger
}

func NewUserHandler(
	userService *service.UserService,
	oauthService *service.OAuthService,
	tenantService service.TenantService,
	logger logging.Logger,
) *UserHandler {
	return &UserHandler{
		userService:   userService,
		oauthService:  oauthService,
		tenantService: tenantService,
		logger:        logger,
	}
}

// GetProfile godoc
// @Summary Get user profile
// @Description Get current user's profile
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.UserInfo
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me [get]
func (h *UserHandler) GetProfile(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	user, err := h.userService.GetProfile(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.OK(c, toUserInfo(user))
}

// UpdateProfile godoc
// @Summary Update user profile
// @Description Update current user's profile
// @Tags User
// @Accept json
// @Produce json
// @Param request body dto.UpdateProfileRequest true "Profile data"
// @Security BearerAuth
// @Success 200 {object} dto.UserInfo
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me [put]
func (h *UserHandler) UpdateProfile(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	var req dto.UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	user, err := h.userService.UpdateProfile(c.Context(), userID, &service.UpdateProfileRequest{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Avatar:    req.Avatar,
		Birthday:  req.Birthday,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(toUserInfo(user))
}

// ChangePassword godoc
// @Summary Change password
// @Description Change current user's password
// @Tags User
// @Accept json
// @Produce json
// @Param request body dto.ChangePasswordRequest true "Password data"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/password [put]
func (h *UserHandler) ChangePassword(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	var req dto.ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	err := h.userService.ChangePassword(c.Context(), userID, &service.ChangePasswordRequest{
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "Password changed successfully",
	})
}

// SetPassword godoc
// @Summary Set password
// @Description Set password for users who don't have one (OTP users)
// @Tags User
// @Accept json
// @Produce json
// @Param request body dto.SetPasswordRequest true "Password data"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/password/set [post]
func (h *UserHandler) SetPassword(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	var req dto.SetPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	err := h.userService.SetPassword(c.Context(), userID, &service.SetPasswordRequest{
		Password: req.Password,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "Password set successfully",
	})
}

// GetSessions godoc
// @Summary Get user sessions
// @Description Get current user's active sessions
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {array} object
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/sessions [get]
func (h *UserHandler) GetSessions(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	sessions, err := h.userService.GetUserSessions(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(sessions)
}

// GetTwoFactorStatus godoc
// @Summary Get 2FA status
// @Description Get the current two-factor authentication status (and pending secret)
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} service.TwoFactorStatus
// @Router /users/me/2fa/status [get]
func (h *UserHandler) GetTwoFactorStatus(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	status, err := h.userService.GetTwoFactorStatus(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(status)
}

// SetupTwoFactor godoc
// @Summary Start 2FA setup
// @Description Generate and persist a TOTP secret; returns the provisioning URI
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} service.TwoFactorStatus
// @Router /users/me/2fa/setup [post]
func (h *UserHandler) SetupTwoFactor(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	status, err := h.userService.SetupTwoFactor(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(status)
}

// EnableTwoFactor godoc
// @Summary Enable 2FA
// @Description Verify the current TOTP code and enable two-factor authentication
// @Tags User
// @Accept json
// @Produce json
// @Param request body dto.TwoFactorCodeRequest true "TOTP code"
// @Security BearerAuth
// @Success 200 {object} service.TwoFactorStatus
// @Router /users/me/2fa/enable [post]
func (h *UserHandler) EnableTwoFactor(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var req dto.TwoFactorCodeRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}
	status, err := h.userService.EnableTwoFactor(c.Context(), userID, req.Code)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(status)
}

// DisableTwoFactor godoc
// @Summary Disable 2FA
// @Description Verify the current TOTP code and disable two-factor authentication
// @Tags User
// @Accept json
// @Produce json
// @Param request body dto.TwoFactorCodeRequest true "TOTP code"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Router /users/me/2fa/disable [post]
func (h *UserHandler) DisableTwoFactor(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	var req dto.TwoFactorCodeRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}
	if err := h.userService.DisableTwoFactor(c.Context(), userID, req.Code); err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(dto.MessageResponse{Message: "Two-factor authentication disabled"})
}

// GetSecurityEvents godoc
// @Summary Get security events
// @Description Get recent login/security events for the current user
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {array} service.SecurityEvent
// @Router /users/me/security-events [get]
func (h *UserHandler) GetSecurityEvents(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}
	events, err := h.userService.GetSecurityEvents(c.Context(), userID, c.QueryInt("limit", 20))
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	if events == nil {
		events = []service.SecurityEvent{}
	}
	return c.JSON(events)
}

// RevokeSession godoc
// @Summary Revoke a session
// @Description Log out a specific session belonging to the current user
// @Tags User
// @Produce json
// @Param id path string true "Session ID"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /users/me/sessions/{id} [delete]
func (h *UserHandler) RevokeSession(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid session ID")
	}

	if err := h.userService.RevokeUserSession(c.Context(), userID, id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "Session revoked successfully",
	})
}

// GetLinkedAccounts godoc
// @Summary Get linked OAuth accounts
// @Description Get OAuth accounts linked to current user
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {array} object
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/linked-accounts [get]
func (h *UserHandler) GetLinkedAccounts(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	accounts, err := h.oauthService.GetLinkedAccounts(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	// Return sanitized response
	result := make([]map[string]interface{}, len(accounts))
	for i, acc := range accounts {
		result[i] = map[string]interface{}{
			"provider": acc.Provider,
			"email":    acc.Email,
			"linkedAt": acc.CreatedAt,
		}
	}

	return c.JSON(result)
}

// GetMyTenants godoc
// @Summary Get user's tenants
// @Description Get all tenants that the current user is a member of
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {array} object
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/tenants [get]
func (h *UserHandler) GetMyTenants(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	memberships, err := h.tenantService.GetUserTenants(c.Context(), userID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	// Build response with tenant info + user's role in each tenant
	type TenantInfo struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		DisplayName string `json:"displayName,omitempty"`
		Logo        string `json:"logo,omitempty"`
		Status      string `json:"status"`
		Plan        string `json:"plan"`
		IsDefault   bool   `json:"isDefault"`
		Role        string `json:"role,omitempty"`
	}

	result := make([]TenantInfo, 0, len(memberships))
	for _, m := range memberships {
		if m.Tenant == nil {
			continue
		}
		roleName := "member"
		if m.Role != nil {
			roleName = m.Role.Name
		}
		if m.IsOwner {
			roleName = "owner"
		}
		result = append(result, TenantInfo{
			ID:          m.Tenant.ID.String(),
			Name:        m.Tenant.Name,
			Slug:        m.Tenant.Slug,
			DisplayName: m.Tenant.DisplayName,
			Logo:        m.Tenant.Logo,
			Status:      string(m.Tenant.Status),
			Plan:        m.Tenant.Plan,
			IsDefault:   m.IsDefault,
			Role:        roleName,
		})
	}

	return c.JSON(result)
}

// UnlinkGoogleAccount godoc
// @Summary Unlink Google account
// @Description Unlink Google OAuth account from current user
// @Tags User
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /users/me/linked-accounts/google [delete]
func (h *UserHandler) UnlinkGoogleAccount(c *fiber.Ctx) error {
	userID := getUserIDFromContext(c)
	if userID == uuid.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	if err := h.oauthService.UnlinkGoogleAccount(c.Context(), userID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "Google account unlinked successfully",
	})
}

// Helper function
func getUserIDFromContext(c *fiber.Ctx) uuid.UUID {
	userIDStr, ok := c.Locals("userId").(string)
	if !ok {
		return uuid.Nil
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil
	}
	return userID
}

func toUserInfo(user interface{}) *dto.UserInfo {
	if user == nil {
		return nil
	}

	switch u := user.(type) {
	case *models.User:
		roles := make([]string, 0, len(u.Roles))
		for _, r := range u.Roles {
			roles = append(roles, r.Name)
		}
		phone := ""
		if u.Phone != nil {
			phone = *u.Phone
		}
		return &dto.UserInfo{
			ID:            u.ID.String(),
			Email:         u.Email,
			Username:      u.Username,
			FirstName:     u.FirstName,
			LastName:      u.LastName,
			Phone:         phone,
			Avatar:        u.Avatar,
			Birthday:      u.Birthday,
			EmailVerified: u.EmailVerified,
			PhoneVerified: u.PhoneVerified,
			Roles:         roles,
			Metadata:      u.Metadata,
		}
	case interface {
		GetID() string
		GetEmail() string
		GetUsername() string
		GetFirstName() string
		GetLastName() string
		GetPhone() string
		GetAvatar() string
		IsEmailVerified() bool
		IsPhoneVerified() bool
		GetRoleNames() []string
	}:
		return &dto.UserInfo{
			ID:            u.GetID(),
			Email:         u.GetEmail(),
			Username:      u.GetUsername(),
			FirstName:     u.GetFirstName(),
			LastName:      u.GetLastName(),
			Phone:         u.GetPhone(),
			Avatar:        u.GetAvatar(),
			EmailVerified: u.IsEmailVerified(),
			PhoneVerified: u.IsPhoneVerified(),
			Roles:         u.GetRoleNames(),
		}
	default:
		return nil
	}
}
