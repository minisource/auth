package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/minisource/auth/internal/models"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

type AdminOAuthProviderHandler struct {
	oauthProviderService service.OAuthProviderService
	logger               logging.Logger
}

func NewAdminOAuthProviderHandler(
	oauthProviderService service.OAuthProviderService,
	logger logging.Logger,
) *AdminOAuthProviderHandler {
	return &AdminOAuthProviderHandler{
		oauthProviderService: oauthProviderService,
		logger:               logger,
	}
}

func (h *AdminOAuthProviderHandler) ListOAuthProviders(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	pageSize := c.QueryInt("pageSize", 20)

	var tenantID *uuid.UUID
	if tenantIDStr := c.Query("tenantId"); tenantIDStr != "" {
		parsed, err := uuid.Parse(tenantIDStr)
		if err != nil {
			return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
		}
		tenantID = &parsed
	}

	providers, total, err := h.oauthProviderService.List(c.Context(), tenantID, page, pageSize)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	return response.New().Data(fiber.Map{
		"data": providers,
		"meta": fiber.Map{
			"page":       page,
			"pageSize":   pageSize,
			"total":      total,
			"totalPages": totalPages,
		},
	}).Send(c)
}

func (h *AdminOAuthProviderHandler) GetOAuthProvider(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid provider ID")
	}

	provider, err := h.oauthProviderService.GetByID(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(provider).Send(c)
}

func (h *AdminOAuthProviderHandler) CreateOAuthProvider(c *fiber.Ctx) error {
	var req struct {
		Name         string                     `json:"name"`
		Type         string                     `json:"type"`
		ClientID     string                     `json:"clientId"`
		ClientSecret string                     `json:"clientSecret"`
		RedirectURL  string                     `json:"redirectUrl"`
		Scopes       string                     `json:"scopes"`
		AuthURL      string                     `json:"authUrl"`
		TokenURL     string                     `json:"tokenUrl"`
		UserInfoURL  string                     `json:"userInfoUrl"`
		TenantID     *string                    `json:"tenantId"`
		Config       models.OAuthProviderConfig `json:"config"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	if req.Name == "" || req.Type == "" || req.ClientID == "" || req.ClientSecret == "" {
		return response.BadRequest(c, "VALIDATION_ERROR", "Name, type, clientId, and clientSecret are required")
	}

	provider := &models.OAuthProvider{
		Name:         req.Name,
		Type:         req.Type,
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		RedirectURL:  req.RedirectURL,
		Scopes:       req.Scopes,
		AuthURL:      req.AuthURL,
		TokenURL:     req.TokenURL,
		UserInfoURL:  req.UserInfoURL,
		IsEnabled:    true,
		Config:       req.Config,
	}

	if req.TenantID != nil {
		tenantUUID, err := uuid.Parse(*req.TenantID)
		if err != nil {
			return response.BadRequest(c, "INVALID_REQUEST", "Invalid tenant ID")
		}
		provider.TenantID = &tenantUUID
	}

	created, err := h.oauthProviderService.Create(c.Context(), provider)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, created)
}

func (h *AdminOAuthProviderHandler) UpdateOAuthProvider(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid provider ID")
	}

	var req struct {
		Name         string                     `json:"name"`
		ClientID     string                     `json:"clientId"`
		ClientSecret string                     `json:"clientSecret"`
		RedirectURL  string                     `json:"redirectUrl"`
		Scopes       string                     `json:"scopes"`
		AuthURL      string                     `json:"authUrl"`
		TokenURL     string                     `json:"tokenUrl"`
		UserInfoURL  string                     `json:"userInfoUrl"`
		Config       models.OAuthProviderConfig `json:"config"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	updates := make(map[string]interface{})
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.ClientID != "" {
		updates["clientId"] = req.ClientID
	}
	if req.ClientSecret != "" {
		updates["clientSecret"] = req.ClientSecret
	}
	if req.RedirectURL != "" {
		updates["redirectUrl"] = req.RedirectURL
	}
	if req.Scopes != "" {
		updates["scopes"] = req.Scopes
	}
	if req.AuthURL != "" {
		updates["authUrl"] = req.AuthURL
	}
	if req.TokenURL != "" {
		updates["tokenUrl"] = req.TokenURL
	}
	if req.UserInfoURL != "" {
		updates["userInfoUrl"] = req.UserInfoURL
	}
	if req.Config != nil {
		updates["config"] = req.Config
	}

	updated, err := h.oauthProviderService.Update(c.Context(), id, updates)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(updated).Send(c)
}

func (h *AdminOAuthProviderHandler) DeleteOAuthProvider(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid provider ID")
	}

	if err := h.oauthProviderService.Delete(c.Context(), id); err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return c.SendStatus(fiber.StatusNoContent)
}

func (h *AdminOAuthProviderHandler) ToggleOAuthProvider(c *fiber.Ctx) error {
	id, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid provider ID")
	}

	provider, err := h.oauthProviderService.ToggleEnabled(c.Context(), id)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.New().Data(fiber.Map{
		"id":        provider.ID,
		"isEnabled": provider.IsEnabled,
	}).Send(c)
}
