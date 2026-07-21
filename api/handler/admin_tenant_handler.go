package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// AdminTenantHandler handles admin tenant management endpoints
type AdminTenantHandler struct {
	tenantService service.TenantService
	logger        logging.Logger
}

func NewAdminTenantHandler(
	tenantService service.TenantService,
	logger logging.Logger,
) *AdminTenantHandler {
	return &AdminTenantHandler{
		tenantService: tenantService,
		logger:        logger,
	}
}

// ListTenants godoc
// @Summary List tenants
// @Description List all tenants with pagination
// @Tags Admin/Tenants
// @Produce json
// @Param page query int false "Page number"
// @Param pageSize query int false "Page size"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants [get]
func (h *AdminTenantHandler) ListTenants(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("pageSize", 20)

	tenants, total, err := h.tenantService.ListTenants(c.Context(), page, pageSize)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	return response.New().Data(fiber.Map{
		"data": tenants,
		"meta": fiber.Map{
			"page":       page,
			"pageSize":   pageSize,
			"total":      total,
			"totalPages": totalPages,
		},
	}).Send(c)
}

// GetTenant godoc
// @Summary Get tenant by ID
// @Description Get tenant details
// @Tags Admin/Tenants
// @Produce json
// @Param id path string true "Tenant ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/tenants/{id} [get]
func (h *AdminTenantHandler) GetTenant(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	tenant, err := h.tenantService.GetTenantByID(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(tenant).Send(c)
}

// CreateTenant godoc
// @Summary Create tenant
// @Description Create a new tenant
// @Tags Admin/Tenants
// @Accept json
// @Produce json
// @Param request body object true "Tenant data"
// @Security BearerAuth
// @Success 201 {object} response.Response
// @Failure 400 {object} response.Response
// @Router /admin/tenants [post]
func (h *AdminTenantHandler) CreateTenant(c *fiber.Ctx) error {
	var req struct {
		Name        string `json:"name" validate:"required"`
		Slug        string `json:"slug" validate:"required"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
		Domain      string `json:"domain"`
		ContactEmail string `json:"contactEmail"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	if req.Name == "" || req.Slug == "" {
		return response.BadRequest(c, "VALIDATION_ERROR", "Name and slug are required")
	}

	// Get current user from context
	userIDStr, ok := c.Locals("userId").(string)
	if !ok {
		return response.Unauthorized(c, "Unauthorized")
	}
	ownerID, err := uuid.Parse(userIDStr)
	if err != nil {
		return response.Unauthorized(c, "Unauthorized")
	}

	tenant, err := h.tenantService.CreateTenant(c.Context(), req.Name, req.Slug, ownerID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, tenant)
}

// UpdateTenant godoc
// @Summary Update tenant
// @Description Update tenant details
// @Tags Admin/Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param request body object true "Tenant update data"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/tenants/{id} [put]
func (h *AdminTenantHandler) UpdateTenant(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	var req struct {
		Name        string            `json:"name"`
		DisplayName string            `json:"displayName"`
		Description string            `json:"description"`
		Domain      string            `json:"domain"`
		Status      models.TenantStatus `json:"status"`
		Settings    *models.TenantSettings `json:"settings"`
		Logo        string            `json:"logo"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	updates := make(map[string]interface{})
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Domain != "" {
		updates["domain"] = req.Domain
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}

	if _, err := h.tenantService.UpdateTenant(c.Context(), id, updates); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	// Update status if provided
	if req.Status != "" {
		if err := h.tenantService.SetTenantStatus(c.Context(), id, req.Status); err != nil {
			return handleAuthError(c, err, h.logger)
		}
	}

	// Update settings if provided
	if req.Settings != nil {
		if err := h.tenantService.UpdateSettings(c.Context(), id, *req.Settings); err != nil {
			return handleAuthError(c, err, h.logger)
		}
	}

	// Re-fetch to return latest state
	tenant, err := h.tenantService.GetTenantByID(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(tenant).Send(c)
}

// DeleteTenant godoc
// @Summary Delete tenant
// @Description Delete a tenant
// @Tags Admin/Tenants
// @Param id path string true "Tenant ID"
// @Security BearerAuth
// @Success 204
// @Failure 404 {object} response.Response
// @Router /admin/tenants/{id} [delete]
func (h *AdminTenantHandler) DeleteTenant(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	if err := h.tenantService.DeleteTenant(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ToggleTenantStatus godoc
// @Summary Toggle tenant status
// @Description Activate or deactivate a tenant
// @Tags Admin/Tenants
// @Param id path string true "Tenant ID"
// @Param status path string true "Status (active/inactive/suspended)"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/status/{status} [patch]
func (h *AdminTenantHandler) ToggleTenantStatus(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	status := models.TenantStatus(c.Params("status"))
	if status != models.TenantStatusActive && status != models.TenantStatusInactive && status != models.TenantStatusSuspended {
		return response.BadRequest(c, "INVALID_STATUS", "Status must be active, inactive, or suspended")
	}

	if err := h.tenantService.SetTenantStatus(c.Context(), id, status); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{"status": status}).Send(c)
}

// === Tenant Members ===

// ListTenantMembers godoc
// @Summary List tenant members
// @Description List all members of a tenant
// @Tags Admin/Tenants
// @Produce json
// @Param id path string true "Tenant ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/members [get]
func (h *AdminTenantHandler) ListTenantMembers(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	members, err := h.tenantService.GetTenantMembers(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(members).Send(c)
}

// AddTenantMember godoc
// @Summary Add member to tenant
// @Description Add a user as a member of a tenant
// @Tags Admin/Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param request body object true "Member data"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/members [post]
func (h *AdminTenantHandler) AddTenantMember(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	var req struct {
		UserID string `json:"userId" validate:"required"`
		RoleID string `json:"roleId"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	var roleID *uuid.UUID
	if req.RoleID != "" {
		parsed, err := uuid.Parse(req.RoleID)
		if err == nil {
			roleID = &parsed
		}
	}

	if err := h.tenantService.AddMember(c.Context(), tenantID, userID, roleID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{"message": "Member added successfully"}).Send(c)
}

// UpdateTenantMember godoc
// @Summary Update tenant member
// @Description Update a member's role in a tenant
// @Tags Admin/Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param userId path string true "User ID"
// @Param request body object true "Member update data"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/members/{userId} [patch]
func (h *AdminTenantHandler) UpdateTenantMember(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	userID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	var req struct {
		RoleID string `json:"roleId"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid role ID")
	}

	if err := h.tenantService.UpdateMemberRole(c.Context(), tenantID, userID, roleID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{"message": "Member updated successfully"}).Send(c)
}

// RemoveTenantMember godoc
// @Summary Remove member from tenant
// @Description Remove a user from a tenant
// @Tags Admin/Tenants
// @Param id path string true "Tenant ID"
// @Param userId path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/members/{userId} [delete]
func (h *AdminTenantHandler) RemoveTenantMember(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	userID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid user ID")
	}

	if err := h.tenantService.RemoveMember(c.Context(), tenantID, userID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{"message": "Member removed successfully"}).Send(c)
}

// === Tenant Invitations ===

// ListTenantInvitations godoc
// @Summary List tenant invitations
// @Description List pending invitations for a tenant
// @Tags Admin/Tenants
// @Produce json
// @Param id path string true "Tenant ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/invitations [get]
func (h *AdminTenantHandler) ListTenantInvitations(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	invitations, err := h.tenantService.GetPendingInvitations(c.Context(), tenantID)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(invitations).Send(c)
}

// InviteTenantMember godoc
// @Summary Invite member to tenant
// @Description Send an invitation to join a tenant
// @Tags Admin/Tenants
// @Accept json
// @Produce json
// @Param id path string true "Tenant ID"
// @Param request body object true "Invitation data"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/invitations [post]
func (h *AdminTenantHandler) InviteTenantMember(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
	}

	var req struct {
		Email string `json:"email" validate:"required"`
		Role  string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	if req.Email == "" {
		return response.BadRequest(c, "VALIDATION_ERROR", "Email is required")
	}

	userIDStr, ok := c.Locals("userId").(string)
	if !ok {
		return response.Unauthorized(c, "Unauthorized")
	}
	invitedBy, _ := uuid.Parse(userIDStr)

	invitation, err := h.tenantService.InviteMember(c.Context(), tenantID, req.Email, req.Role, invitedBy)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, invitation)
}

// RevokeTenantInvitation godoc
// @Summary Revoke tenant invitation
// @Description Revoke a pending invitation
// @Tags Admin/Tenants
// @Param id path string true "Tenant ID"
// @Param invitationId path string true "Invitation ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tenants/{id}/invitations/{invitationId} [delete]
func (h *AdminTenantHandler) RevokeTenantInvitation(c *fiber.Ctx) error {
	invitationID, err := uuid.Parse(c.Params("invitationId"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid invitation ID")
	}

	if err := h.tenantService.RevokeInvitation(c.Context(), invitationID); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{"message": "Invitation revoked"}).Send(c)
}
