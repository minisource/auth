package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// AdminUserHandler handles admin user management endpoints
type AdminUserHandler struct {
	userService *service.UserService
	logger      logging.Logger
}

func NewAdminUserHandler(
	userService *service.UserService,
	logger logging.Logger,
) *AdminUserHandler {
	return &AdminUserHandler{
		userService: userService,
		logger:      logger,
	}
}

// ListUsers godoc
// @Summary List users
// @Description List all users with pagination
// @Tags Admin/Users
// @Produce json
// @Param page query int false "Page number"
// @Param pageSize query int false "Page size"
// @Param search query string false "Search query"
// @Param roleId query string false "Filter by role ID"
// @Param isActive query bool false "Filter by active status"
// @Security BearerAuth
// @Success 200 {object} service.ListUsersResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 403 {object} dto.ErrorResponse
// @Router /admin/users [get]
func (h *AdminUserHandler) ListUsers(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("pageSize", 20)
	search := c.Query("search")
	roleIDStr := c.Query("roleId")

	var roleID uuid.UUID
	if roleIDStr != "" {
		roleID, _ = uuid.Parse(roleIDStr)
	}

	var isActive *bool
	if c.Query("isActive") != "" {
		active := c.QueryBool("isActive")
		isActive = &active
	}

	resp, err := h.userService.ListUsers(c.Context(), &service.ListUsersRequest{
		Page:     page,
		PageSize: pageSize,
		Search:   search,
		RoleID:   roleID,
		IsActive: isActive,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(resp)
}

// GetUser godoc
// @Summary Get user by ID
// @Description Get user details by ID
// @Tags Admin/Users
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} dto.UserInfo
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/users/{id} [get]
func (h *AdminUserHandler) GetUser(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	user, err := h.userService.GetUserByID(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(user)
}

// CreateUser godoc
// @Summary Create user
// @Description Create a new user
// @Tags Admin/Users
// @Accept json
// @Produce json
// @Param request body dto.CreateUserRequest true "User data"
// @Security BearerAuth
// @Success 201 {object} dto.UserInfo
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Router /admin/users [post]
func (h *AdminUserHandler) CreateUser(c *fiber.Ctx) error {
	var req dto.CreateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	user, err := h.userService.CreateUser(c.Context(), &service.CreateUserRequest{
		Email:     req.Email,
		Password:  req.Password,
		Username:  req.Username,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Phone:     req.Phone,
		RoleIDs:   req.RoleIDs,
		IsActive:  req.IsActive,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, user)
}

// UpdateUser godoc
// @Summary Update user
// @Description Update user by ID
// @Tags Admin/Users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body dto.UpdateUserRequest true "User data"
// @Security BearerAuth
// @Success 200 {object} dto.UserInfo
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/users/{id} [put]
func (h *AdminUserHandler) UpdateUser(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	var req dto.UpdateUserRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	user, err := h.userService.UpdateUser(c.Context(), id, &service.UpdateUserRequest{
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Phone:         req.Phone,
		IsActive:      req.IsActive,
		EmailVerified: req.EmailVerified,
		PhoneVerified: req.PhoneVerified,
		RoleIDs:       req.RoleIDs,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(user)
}

// DeleteUser godoc
// @Summary Delete user
// @Description Soft delete user by ID
// @Tags Admin/Users
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 204
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/users/{id} [delete]
func (h *AdminUserHandler) DeleteUser(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	if err := h.userService.DeleteUser(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ToggleUserStatus godoc
// @Summary Toggle user status
// @Description Enable or disable user account
// @Tags Admin/Users
// @Param id path string true "User ID"
// @Param status path string true "Status (enable/disable)"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/users/{id}/status/{status} [patch]
func (h *AdminUserHandler) ToggleUserStatus(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	status := c.Params("status")
	isActive := status == "enable"

	if err := h.userService.ToggleUserStatus(c.Context(), id, isActive); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "User status updated",
	})
}

// UnlockUser godoc
// @Summary Unlock user
// @Description Unlock a locked user account
// @Tags Admin/Users
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/users/{id}/unlock [post]
func (h *AdminUserHandler) UnlockUser(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	if err := h.userService.UnlockUser(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "User unlocked",
	})
}
