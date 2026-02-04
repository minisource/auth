package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// UserHandler handles user endpoints
type UserHandler struct {
	userService  *service.UserService
	oauthService *service.OAuthService
	logger       logging.Logger
}

func NewUserHandler(
	userService *service.UserService,
	oauthService *service.OAuthService,
	logger logging.Logger,
) *UserHandler {
	return &UserHandler{
		userService:  userService,
		oauthService: oauthService,
		logger:       logger,
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

	return c.JSON(toUserInfo(user))
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
// @Success 200 {array} github_com_minisource_auth_internal_models.Session
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

	// Type assertion based on what type is passed
	switch u := user.(type) {
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
