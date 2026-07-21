package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/internal/service"
	"github.com/minisource/go-common/logging"
	"github.com/minisource/go-common/response"
)

// AdminToolsHandler handles admin tools endpoints
type AdminToolsHandler struct {
	tokenService  *service.TokenService
	keyProvider   *service.KeyProvider
	authService   *service.AuthService
	roleService   *service.RoleService
	logger        logging.Logger
}

func NewAdminToolsHandler(
	tokenService *service.TokenService,
	keyProvider *service.KeyProvider,
	authService *service.AuthService,
	roleService *service.RoleService,
	logger logging.Logger,
) *AdminToolsHandler {
	return &AdminToolsHandler{
		tokenService: tokenService,
		keyProvider:  keyProvider,
		authService:  authService,
		roleService:  roleService,
		logger:       logger,
	}
}

// IntrospectToken godoc
// @Summary Introspect a token
// @Description Validate and decode any JWT token
// @Tags Admin/Tools
// @Accept json
// @Produce json
// @Param request body object true "Token to introspect"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tools/introspect-token [post]
func (h *AdminToolsHandler) IntrospectToken(c *fiber.Ctx) error {
	var req struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	if req.Token == "" {
		return response.BadRequest(c, "VALIDATION_ERROR", "Token is required")
	}

	claims, err := h.tokenService.ValidateToken(req.Token)
	if err != nil {
		return c.JSON(fiber.Map{
			"active": false,
			"error":  err.Error(),
		})
	}

	scopes := append(append([]string{}, claims.Roles...), claims.Permissions...)
	expiresAt := int64(0)
	if claims.ExpiresAt != nil {
		expiresAt = claims.ExpiresAt.Unix()
	}

	return c.JSON(fiber.Map{
		"active":      true,
		"sub":         claims.UserID,
		"email":       claims.Email,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
		"scopes":      scopes,
		"exp":         expiresAt,
		"tokenType":   claims.TokenType,
		"sessionId":   claims.SessionID,
	})
}

// CheckPermission godoc
// @Summary Check permission
// @Description Check if a token has a specific permission
// @Tags Admin/Tools
// @Accept json
// @Produce json
// @Param request body object true "Permission check request"
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tools/check-permission [post]
func (h *AdminToolsHandler) CheckPermission(c *fiber.Ctx) error {
	var req struct {
		RoleName     string `json:"roleName" validate:"required"`
		Permission   string `json:"permission" validate:"required"`
	}
	if err := c.BodyParser(&req); err != nil {
		return response.BadRequest(c, "INVALID_REQUEST", "Invalid request body")
	}

	if req.RoleName == "" || req.Permission == "" {
		return response.BadRequest(c, "VALIDATION_ERROR", "roleName and permission are required")
	}

	role, err := h.roleService.GetRoleByName(c.Context(), req.RoleName)
	if err != nil {
		return handleAuthError(c, err, h.logger)
	}
	if role == nil {
		return c.JSON(fiber.Map{
			"exists":       false,
			"hasPermission": false,
			"message":      "Role not found",
		})
	}

	hasPerm, err := h.roleService.HasPermission(c.Context(), role.ID, req.Permission)
	if err != nil {
		return response.InternalError(c, "Failed to check permission")
	}

	return c.JSON(fiber.Map{
		"exists":       true,
		"roleName":     role.Name,
		"hasPermission": hasPerm,
	})
}

// JWKSStatus godoc
// @Summary JWKS status
// @Description Get JWKS key information
// @Tags Admin/Tools
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tools/jwks-status [get]
func (h *AdminToolsHandler) JWKSStatus(c *fiber.Ctx) error {
	cfg := struct {
		Algorithm string `json:"algorithm"`
		KeyID     string `json:"keyId"`
		Issuer    string `json:"issuer"`
		HasPublicKey bool `json:"hasPublicKey"`
	}{
		Algorithm:    h.keyProvider.GetKeyID(), // This is actually the key ID — we can't easily expose the algorithm
		HasPublicKey: false,
	}

	// Try to determine signing method info
	if sm := h.keyProvider.GetSigningMethod(); sm != nil {
		cfg.Algorithm = sm.Alg()
	}

	kid := h.keyProvider.GetKeyID()
	cfg.KeyID = kid

	return response.New().Data(cfg).Send(c)
}

// ToolsHealth godoc
// @Summary Service health info
// @Description Get detailed service health information
// @Tags Admin/Tools
// @Produce json
// @Security BearerAuth
// @Success 200 {object} response.Response
// @Router /admin/tools/health [get]
func (h *AdminToolsHandler) ToolsHealth(c *fiber.Ctx) error {
	return response.New().Data(fiber.Map{
		"status":  "healthy",
		"service": "auth-service",
	}).Send(c)
}
