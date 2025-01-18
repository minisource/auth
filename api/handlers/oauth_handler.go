package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/services"
	"github.com/minisource/common_go/http/helper"
)

type OAuthHandler struct {
	service *services.OAuthService
}

func NewOAuthHandler(cfg *config.Config) *OAuthHandler {
	service := services.NewOAuthService(cfg)
	return &OAuthHandler{service: service}
}

// Create OAuthClient godoc
// @Summary Create OAuthClient
// @Description Create OAuthClient
// @Tags OAuthClient
// @Accept  json
// @Produce  json
// @Success 200 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/oauth/ [post]
func (h *OAuthHandler) Create(c *fiber.Ctx) error {
	req := new(dto.CreateOAuthClientRequest)

	// Parse the request body
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err),
		)
	}

	// Call the service to create the OAuth client
	client, err := h.service.CreateClient(req)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return the created client
	return c.Status(fiber.StatusCreated).JSON(
		helper.GenerateBaseResponse(client, true, helper.Success),
	)
}

// GetAll OAuthClients godoc
// @Summary Create OAuthClients
// @Description Create OAuthClients
// @Tags OAuthClients
// @Accept  json
// @Produce  json
// @Success 200 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/oauth/ [get]
func (h *OAuthHandler) GetAll(c *fiber.Ctx) error {
	// Call the service to get all OAuth clients
	clients, err := h.service.GetAllClients()
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return the list of clients
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(clients, true, helper.Success),
	)
}

// Delete OAuthClient godoc
// @Summary Delete OAuthClient
// @Description Delete OAuthClient by ID
// @Tags OAuthClient
// @Accept  json
// @Produce  json
// @Param id path string true "OAuthClient ID"
// @Success 200 {object} helper.BaseHttpResponse "Success"
// @Failure 400 {object} helper.BaseHttpResponse "Failed"
// @Router /v1/oauth/{id} [delete]
func (h *OAuthHandler) Delete(c *fiber.Ctx) error {
	// Get the ID from the URL parameters
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusNotFound).JSON(
			helper.GenerateBaseResponse(nil, false, helper.ValidationError),
		)
	}

	// Call the service to delete the OAuth client
	err := h.service.DeleteClient(id)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return a success response
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(nil, true, 0),
	)
}

// GetOAuthClient godoc
// @Summary Get a OAuthClient
// @Description Get a OAuthClient by ID
// @Tags OAuthClient
// @Accept json
// @Produce json
// @Param id path string true "OAuthClient ID"
// @Success 200 {object} helper.BaseHttpResponse{result=dto.GetOAuthClientResponse} "GetOAuthClient response"
// @Failure 400 {object} helper.BaseHttpResponse "Bad request"
// @Failure 404 {object} helper.BaseHttpResponse "Not found"
// @Router /v1/oauth/{id} [get]
func (h *OAuthHandler) GetById(c *fiber.Ctx) error {
	// Get the ID from the URL parameters
	id := c.Params("id")
	if id == "" {
		return c.Status(fiber.StatusNotFound).JSON(
			helper.GenerateBaseResponse(nil, false, helper.ValidationError),
		)
	}

	// Call the service to get the OAuth client
	client, err := h.service.GetClient(id)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return the OAuth client
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(client, true, 0),
	)
}

// GenerateOAuthToken godoc
// @Summary Generate an OAuthClientToken
// @Description Generate an OAuthClientToken
// @Tags OAuthClientToken
// @Accept json
// @Produce json
// @Failure 400 {object} helper.BaseHttpResponse "Bad request"
// @Failure 404 {object} helper.BaseHttpResponse "Not found"
// @Router /v1/oauth/GenerateToken [post]
func (h *OAuthHandler) GenerateToken(c *fiber.Ctx) error {
	// Parse the request body
	req := new(dto.GenerateTokenRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err),
		)
	}

	// Call the service to generate the token
	token, err := h.service.GenerateToken(req)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return the generated token
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(token, true, 0),
	)
}

// ValidateToken godoc
// @Summary ValidateToken
// @Description ValidateToken
// @Tags ValidateToken
// @Accept json
// @Produce json
// @Failure 400 {object} helper.BaseHttpResponse "Bad request"
// @Failure 404 {object} helper.BaseHttpResponse "Not found"
// @Router /v1/oauth/ValidateToken [post]
func (h *OAuthHandler) ValidateToken(c *fiber.Ctx) error {
	// Parse the request body
	req := new(dto.ValidateTokenRequest)
	if err := c.BodyParser(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			helper.GenerateBaseResponseWithValidationError(nil, false, helper.ValidationError, err),
		)
	}

	// Call the service to validate the token
	introspection, err := h.service.ValidateToken(*req)
	if err != nil {
		return c.Status(helper.TranslateErrorToStatusCode(err)).JSON(
			helper.GenerateBaseResponseWithError(nil, false, helper.InternalError, err),
		)
	}

	// Return the token introspection result
	return c.Status(fiber.StatusOK).JSON(
		helper.GenerateBaseResponse(introspection, true, 0),
	)
}