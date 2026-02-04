package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// RoleHandler handles role and permission endpoints
type RoleHandler struct {
	roleService *service.RoleService
	logger      logging.Logger
}

func NewRoleHandler(
	roleService *service.RoleService,
	logger logging.Logger,
) *RoleHandler {
	return &RoleHandler{
		roleService: roleService,
		logger:      logger,
	}
}

// === Role Endpoints ===

// ListRoles godoc
// @Summary List roles
// @Description List all roles
// @Tags Admin/Roles
// @Produce json
// @Security BearerAuth
// @Success 200 {array} github_com_minisource_auth_internal_models.Role
// @Failure 401 {object} dto.ErrorResponse
// @Router /admin/roles [get]
func (h *RoleHandler) ListRoles(c *fiber.Ctx) error {
	roles, err := h.roleService.ListRoles(c.Context())
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return c.JSON(roles)
}

// GetRole godoc
// @Summary Get role by ID
// @Description Get role with permissions
// @Tags Admin/Roles
// @Produce json
// @Param id path string true "Role ID"
// @Security BearerAuth
// @Success 200 {object} github_com_minisource_auth_internal_models.Role
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/roles/{id} [get]
func (h *RoleHandler) GetRole(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid role ID")
	}

	role, err := h.roleService.GetRole(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(role)
}

// CreateRole godoc
// @Summary Create role
// @Description Create a new role
// @Tags Admin/Roles
// @Accept json
// @Produce json
// @Param request body dto.CreateRoleRequest true "Role data"
// @Security BearerAuth
// @Success 201 {object} github_com_minisource_auth_internal_models.Role
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Router /admin/roles [post]
func (h *RoleHandler) CreateRole(c *fiber.Ctx) error {
	var req dto.CreateRoleRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	role, err := h.roleService.CreateRole(c.Context(), &service.CreateRoleRequest{
		Name:          req.Name,
		Description:   req.Description,
		PermissionIDs: req.PermissionIDs,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, role)
}

// UpdateRole godoc
// @Summary Update role
// @Description Update role by ID
// @Tags Admin/Roles
// @Accept json
// @Produce json
// @Param id path string true "Role ID"
// @Param request body dto.UpdateRoleRequest true "Role data"
// @Security BearerAuth
// @Success 200 {object} github_com_minisource_auth_internal_models.Role
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/roles/{id} [put]
func (h *RoleHandler) UpdateRole(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid role ID")
	}

	var req dto.UpdateRoleRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	role, err := h.roleService.UpdateRole(c.Context(), id, &service.UpdateRoleRequest{
		Name:          req.Name,
		Description:   req.Description,
		PermissionIDs: req.PermissionIDs,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(role)
}

// DeleteRole godoc
// @Summary Delete role
// @Description Delete role by ID
// @Tags Admin/Roles
// @Param id path string true "Role ID"
// @Security BearerAuth
// @Success 204
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/roles/{id} [delete]
func (h *RoleHandler) DeleteRole(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid role ID")
	}

	if err := h.roleService.DeleteRole(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// === Permission Endpoints ===

// ListPermissions godoc
// @Summary List permissions
// @Description List all permissions
// @Tags Admin/Permissions
// @Produce json
// @Param resource query string false "Filter by resource"
// @Security BearerAuth
// @Success 200 {array} github_com_minisource_auth_internal_models.Permission
// @Failure 401 {object} dto.ErrorResponse
// @Router /admin/permissions [get]
func (h *RoleHandler) ListPermissions(c *fiber.Ctx) error {
	resource := c.Query("resource")

	var permissions []*interface{}
	var err error

	if resource != "" {
		perms, e := h.roleService.ListPermissionsByResource(c.Context(), resource)
		err = e
		for _, p := range perms {
			var v interface{} = p
			permissions = append(permissions, &v)
		}
	} else {
		perms, e := h.roleService.ListPermissions(c.Context())
		err = e
		for _, p := range perms {
			var v interface{} = p
			permissions = append(permissions, &v)
		}
	}

	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(permissions)
}

// GetPermission godoc
// @Summary Get permission by ID
// @Description Get permission details
// @Tags Admin/Permissions
// @Produce json
// @Param id path string true "Permission ID"
// @Security BearerAuth
// @Success 200 {object} github_com_minisource_auth_internal_models.Permission
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/permissions/{id} [get]
func (h *RoleHandler) GetPermission(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid permission ID")
	}

	perm, err := h.roleService.GetPermission(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(perm)
}

// CreatePermission godoc
// @Summary Create permission
// @Description Create a new permission
// @Tags Admin/Permissions
// @Accept json
// @Produce json
// @Param request body dto.CreatePermissionRequest true "Permission data"
// @Security BearerAuth
// @Success 201 {object} github_com_minisource_auth_internal_models.Permission
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Router /admin/permissions [post]
func (h *RoleHandler) CreatePermission(c *fiber.Ctx) error {
	var req dto.CreatePermissionRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	perm, err := h.roleService.CreatePermission(c.Context(), &service.CreatePermissionRequest{
		Name:        req.Name,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, perm)
}

// UpdatePermission godoc
// @Summary Update permission
// @Description Update permission by ID
// @Tags Admin/Permissions
// @Accept json
// @Produce json
// @Param id path string true "Permission ID"
// @Param request body dto.UpdatePermissionRequest true "Permission data"
// @Security BearerAuth
// @Success 200 {object} github_com_minisource_auth_internal_models.Permission
// @Failure 400 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/permissions/{id} [put]
func (h *RoleHandler) UpdatePermission(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid permission ID")
	}

	var req dto.UpdatePermissionRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	perm, err := h.roleService.UpdatePermission(c.Context(), id, &service.UpdatePermissionRequest{
		Name:        req.Name,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
	})
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(perm)
}

// DeletePermission godoc
// @Summary Delete permission
// @Description Delete permission by ID
// @Tags Admin/Permissions
// @Param id path string true "Permission ID"
// @Security BearerAuth
// @Success 204
// @Failure 404 {object} dto.ErrorResponse
// @Router /admin/permissions/{id} [delete]
func (h *RoleHandler) DeletePermission(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid permission ID")
	}

	if err := h.roleService.DeletePermission(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// AssignPermissionToRole godoc
// @Summary Assign permission to role
// @Description Assign a permission to a role
// @Tags Admin/Roles
// @Param roleId path string true "Role ID"
// @Param permissionId path string true "Permission ID"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /admin/roles/{roleId}/permissions/{permissionId} [post]
func (h *RoleHandler) AssignPermissionToRole(c *fiber.Ctx) error {
	roleID, err := uuid.Parse(c.Params("roleId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid role ID")
	}

	permissionID, err := uuid.Parse(c.Params("permissionId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid permission ID")
	}

	if err := h.roleService.AssignPermissionToRole(c.Context(), roleID, permissionID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "Permission assigned to role",
	})
}

// RemovePermissionFromRole godoc
// @Summary Remove permission from role
// @Description Remove a permission from a role
// @Tags Admin/Roles
// @Param roleId path string true "Role ID"
// @Param permissionId path string true "Permission ID"
// @Security BearerAuth
// @Success 200 {object} dto.MessageResponse
// @Failure 400 {object} dto.ErrorResponse
// @Router /admin/roles/{roleId}/permissions/{permissionId} [delete]
func (h *RoleHandler) RemovePermissionFromRole(c *fiber.Ctx) error {
	roleID, err := uuid.Parse(c.Params("roleId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid role ID")
	}

	permissionID, err := uuid.Parse(c.Params("permissionId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid permission ID")
	}

	if err := h.roleService.RemovePermissionFromRole(c.Context(), roleID, permissionID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.JSON(dto.MessageResponse{
		Message: "Permission removed from role",
	})
}
