package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/internal/repository"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// AdminSettingsHandler handles admin settings management endpoints
type AdminSettingsHandler struct {
	settingsService *service.SettingsService
	settingsRepo    repository.SettingRepository
	logger          logging.Logger
}

func NewAdminSettingsHandler(
	settingsService *service.SettingsService,
	settingsRepo repository.SettingRepository,
	logger logging.Logger,
) *AdminSettingsHandler {
	return &AdminSettingsHandler{
		settingsService: settingsService,
		settingsRepo:    settingsRepo,
		logger:          logger,
	}
}

// GetSettings godoc
// @Summary Get all settings
// @Description Get all system settings grouped by category
// @Tags Admin/Settings
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/settings [get]
// sensitiveSettingKeys are settings whose values must never be returned in plaintext.
var sensitiveSettingKeys = map[string]bool{
	"google_client_secret":    true,
	"smtp_password":           true,
	"sms_api_key":             true,
	"jwt_private_key":         true,
	"jwt_private_key_pem":     true,
	"notifier_client_secret":  true,
	"service_client_secret":   true,
}

func (h *AdminSettingsHandler) GetSettings(c *fiber.Ctx) error {
	settings, err := h.settingsRepo.GetAll(c.Context())
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	// Group by category
	grouped := make(map[string][]map[string]interface{})
	for _, s := range settings {
		value := s.Value
		masked := false
		if sensitiveSettingKeys[s.Key] && value != "" {
			value = "********"
			masked = true
		}
		entry := map[string]interface{}{
			"key":         s.Key,
			"value":       value,
			"type":        s.Type,
			"category":    s.Category,
			"description": s.Description,
			"isPublic":    s.IsPublic,
			"isConfigured": s.Value != "",
			"isMasked":    masked,
		}
		cat := s.Category
		if cat == "" {
			cat = "general"
		}
		grouped[cat] = append(grouped[cat], entry)
	}

	return response.New().Data(grouped).Send(c)
}

// GetSettingsByCategory godoc
// @Summary Get settings by category
// @Description Get system settings for a specific category
// @Tags Admin/Settings
// @Produce json
// @Param category path string true "Category name"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/settings/{category} [get]
func (h *AdminSettingsHandler) GetSettingsByCategory(c *fiber.Ctx) error {
	category := c.Params("category")
	if category == "" {
		return response.BadRequest(c, "INVALID_REQUEST", "Category is required")
	}

	settings, err := h.settingsRepo.GetByCategory(c.Context(), category)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	result := make([]map[string]interface{}, 0)
	for _, s := range settings {
		entry := map[string]interface{}{
			"key":         s.Key,
			"value":       s.Value,
			"type":        s.Type,
			"category":    s.Category,
			"description": s.Description,
			"isPublic":    s.IsPublic,
		}
		result = append(result, entry)
	}

	return response.New().Data(result).Send(c)
}

// UpdateSettings godoc
// @Summary Update settings
// @Description Update one or more system settings
// @Tags Admin/Settings
// @Accept json
// @Produce json
// @Param request body object true "Settings key-value pairs"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/settings [patch]
func (h *AdminSettingsHandler) UpdateSettings(c *fiber.Ctx) error {
	var req map[string]string
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	if len(req) == 0 {
		return response.BadRequest(c, "VALIDATION_ERROR", "No settings provided")
	}

	updated := make([]string, 0)
	for key, value := range req {
		// For sensitive keys, don't store empty placeholder values
		if key == "google_client_secret" && value == "" {
			continue
		}
		if err := h.settingsService.Set(c.Context(), key, value); err != nil {
			h.logger.Error(logging.General, logging.Update, "Failed to update setting", map[logging.ExtraKey]interface{}{
				"key":   key,
				"error": err.Error(),
			})
			continue
		}
		updated = append(updated, key)
	}

	// Refresh cache
	h.settingsService.RefreshCache(c.Context())

	return response.New().Data(fiber.Map{
		"message":      "Settings updated successfully",
		"updatedCount": len(updated),
		"updatedKeys":  updated,
	}).Send(c)
}

// UpdateSettingsByCategory godoc
// @Summary Update settings by category
// @Description Update system settings for a specific category
// @Tags Admin/Settings
// @Accept json
// @Produce json
// @Param category path string true "Category name"
// @Param request body object true "Settings key-value pairs"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/settings/{category} [patch]
func (h *AdminSettingsHandler) UpdateSettingsByCategory(c *fiber.Ctx) error {
	category := c.Params("category")
	if category == "" {
		return response.BadRequest(c, "INVALID_REQUEST", "Category is required")
	}

	var req map[string]string
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	updated := make([]string, 0)
	for key, value := range req {
		if err := h.settingsService.Set(c.Context(), key, value); err != nil {
			h.logger.Error(logging.General, logging.Update, "Failed to update setting", map[logging.ExtraKey]interface{}{
				"key":      key,
				"category": category,
				"error":    err.Error(),
			})
			continue
		}
		updated = append(updated, key)
	}

	h.settingsService.RefreshCache(c.Context())

	return response.New().Data(fiber.Map{
		"message":      "Settings updated successfully",
		"updatedCount": len(updated),
		"updatedKeys":  updated,
	}).Send(c)
}
