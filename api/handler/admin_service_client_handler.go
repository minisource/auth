package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// AdminServiceClientHandler handles admin service client management endpoints
type AdminServiceClientHandler struct {
	serviceAuthService *service.ServiceAuthService
	logger             logging.Logger
}

func NewAdminServiceClientHandler(
	serviceAuthService *service.ServiceAuthService,
	logger logging.Logger,
) *AdminServiceClientHandler {
	return &AdminServiceClientHandler{
		serviceAuthService: serviceAuthService,
		logger:             logger,
	}
}

// ListServiceClients godoc
// @Summary List service clients
// @Description List all service clients
// @Tags Admin/ServiceClients
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 401 {object} response.Response
// @Router /admin/service-clients [get]
func (h *AdminServiceClientHandler) ListServiceClients(c *fiber.Ctx) error {
	clients, err := h.serviceAuthService.ListServiceClients(c.Context())
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	return response.New().Data(clients).Send(c)
}

// GetServiceClient godoc
// @Summary Get service client by ID
// @Description Get a service client with details
// @Tags Admin/ServiceClients
// @Produce json
// @Param id path string true "Service Client ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/service-clients/{id} [get]
func (h *AdminServiceClientHandler) GetServiceClient(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid service client ID")
	}

	client, err := h.serviceAuthService.GetServiceClientByID(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(client).Send(c)
}

// UpdateServiceClient godoc
// @Summary Update service client
// @Description Update service client details
// @Tags Admin/ServiceClients
// @Accept json
// @Produce json
// @Param id path string true "Service Client ID"
// @Param request body object true "Service client update data"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 400 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/service-clients/{id} [put]
func (h *AdminServiceClientHandler) UpdateServiceClient(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid service client ID")
	}

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Scopes      []string `json:"scopes"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	client, err := h.serviceAuthService.UpdateServiceClient(c.Context(), id, req.Name, req.Description, req.Scopes)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(client).Send(c)
}

// DeleteServiceClient godoc
// @Summary Delete service client
// @Description Delete/revoke a service client
// @Tags Admin/ServiceClients
// @Param id path string true "Service Client ID"
// @Security BearerAuth
// @Success 204
// @Failure 404 {object} response.Response
// @Router /admin/service-clients/{id} [delete]
func (h *AdminServiceClientHandler) DeleteServiceClient(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid service client ID")
	}

	if err := h.serviceAuthService.DeleteServiceClient(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

// ToggleServiceClientStatus godoc
// @Summary Toggle service client status
// @Description Enable or disable a service client
// @Tags Admin/ServiceClients
// @Param id path string true "Service Client ID"
// @Param status path string true "Status (enable/disable)"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/service-clients/{id}/status/{status} [patch]
func (h *AdminServiceClientHandler) ToggleServiceClientStatus(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid service client ID")
	}

	status := c.Params("status")
	isActive := status == "enable" || status == "active"

	if err := h.serviceAuthService.ToggleServiceClientStatus(c.Context(), id, isActive); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{"isActive": isActive}).Send(c)
}

// RotateServiceClientSecret godoc
// @Summary Rotate service client secret
// @Description Generate a new client secret
// @Tags Admin/ServiceClients
// @Param id path string true "Service Client ID"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Failure 404 {object} response.Response
// @Router /admin/service-clients/{id}/rotate-secret [post]
func (h *AdminServiceClientHandler) RotateServiceClientSecret(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid service client ID")
	}

	clientSecret, err := h.serviceAuthService.RotateServiceClientSecret(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{
		"clientSecret": clientSecret,
		"message":      "Save the client secret - it won't be shown again",
	}).Send(c)
}
