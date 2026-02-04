package handler

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/dto"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// ServiceAuthHandler handles service-to-service authentication
type ServiceAuthHandler struct {
	serviceAuthService *service.ServiceAuthService
	logger             logging.Logger
}

func NewServiceAuthHandler(
	serviceAuthService *service.ServiceAuthService,
	logger logging.Logger,
) *ServiceAuthHandler {
	return &ServiceAuthHandler{
		serviceAuthService: serviceAuthService,
		logger:             logger,
	}
}

// Authenticate godoc
// @Summary Service authentication
// @Description Authenticate service with client credentials
// @Tags Service Auth
// @Accept json
// @Produce json
// @Param request body dto.ServiceAuthRequest true "Client credentials"
// @Success 200 {object} dto.ServiceAuthResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /service/auth [post]
func (h *ServiceAuthHandler) Authenticate(c *fiber.Ctx) error {
	var req dto.ServiceAuthRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	token, expiresAt, err := h.serviceAuthService.AuthenticateService(c.Context(), req.ClientID, req.ClientSecret)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Calculate expires in seconds
	expiresIn := int(time.Until(expiresAt).Seconds())

	return c.JSON(dto.ServiceAuthResponse{
		AccessToken: token,
		ExpiresIn:   expiresIn,
		TokenType:   "Bearer",
	})
}

// ValidateToken godoc
// @Summary Validate service token
// @Description Validate and decode service JWT token
// @Tags Service Auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} object
// @Failure 401 {object} dto.ErrorResponse
// @Router /service/validate [get]
func (h *ServiceAuthHandler) ValidateToken(c *fiber.Ctx) error {
	token := getTokenFromHeader(c)
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "No token provided",
		})
	}

	claims, err := h.serviceAuthService.ValidateServiceToken(c.Context(), token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"valid":       true,
		"clientId":    claims.ClientID,
		"serviceName": claims.Name,
		"scopes":      claims.Scopes,
		"expiresAt":   claims.ExpiresAt,
	})
}

// CreateServiceClient godoc
// @Summary Create service client
// @Description Create a new service client for service-to-service auth
// @Tags Service Auth
// @Accept json
// @Produce json
// @Param request body dto.CreateServiceClientRequest true "Service client data"
// @Security BearerAuth
// @Success 201 {object} object
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Router /admin/service-clients [post]
func (h *ServiceAuthHandler) CreateServiceClient(c *fiber.Ctx) error {
	var req dto.CreateServiceClientRequest
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	client, secret, err := h.serviceAuthService.CreateServiceClient(c.Context(), req.Name, req.Description, req.Scopes)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}

	return response.Created(c, fiber.Map{
		"clientId":     client.ClientID,
		"clientSecret": secret,
		"name":         client.Name,
		"scopes":       client.Scopes,
		"message":      "Save the client secret - it won't be shown again",
	})
}

// HealthHandler handles health check endpoints
type HealthHandler struct {
	db    interface{ Ping() error }
	redis interface{ Ping() error }
}

// HealthChecker interface for components that can be health-checked
type HealthChecker interface {
	Ping() error
}

func NewHealthHandler(db HealthChecker, redis HealthChecker) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
	}
}

// Health godoc
// @Summary Health check
// @Description Check if service is healthy
// @Tags Health
// @Produce json
// @Success 200 {object} object
// @Router /health [get]
func (h *HealthHandler) Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "healthy",
	})
}

// Ready godoc
// @Summary Readiness check
// @Description Check if service is ready
// @Tags Health
// @Produce json
// @Success 200 {object} object
// @Router /ready [get]
func (h *HealthHandler) Ready(c *fiber.Ctx) error {
	checks := fiber.Map{
		"database": "ok",
		"redis":    "ok",
	}

	// Check database connectivity
	if h.db != nil {
		if err := h.db.Ping(); err != nil {
			checks["database"] = "error: " + err.Error()
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "not ready",
				"checks": checks,
			})
		}
	}

	// Check Redis connectivity
	if h.redis != nil {
		if err := h.redis.Ping(); err != nil {
			checks["redis"] = "error: " + err.Error()
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "not ready",
				"checks": checks,
			})
		}
	}

	return c.JSON(fiber.Map{
		"status": "ready",
		"checks": checks,
	})
}
