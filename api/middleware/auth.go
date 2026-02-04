package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/internal/service"
)

// AuthMiddleware creates JWT authentication middleware
func AuthMiddleware(tokenService *service.TokenService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := extractToken(c)
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "No token provided",
			})
		}

		claims, err := tokenService.ValidateToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token",
			})
		}

		// Set user info in context
		c.Locals("userId", claims.UserID)
		c.Locals("sessionId", claims.SessionID)
		c.Locals("email", claims.Email)
		c.Locals("roles", claims.Roles)
		c.Locals("permissions", claims.Permissions)

		return c.Next()
	}
}

// ServiceAuthMiddleware creates service-to-service authentication middleware
func ServiceAuthMiddleware(serviceAuthService *service.ServiceAuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := extractToken(c)
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "No token provided",
			})
		}

		claims, err := serviceAuthService.ValidateServiceToken(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid service token",
			})
		}

		// Set service info in context
		c.Locals("clientId", claims.ClientID)
		c.Locals("serviceName", claims.Name)
		c.Locals("scopes", claims.Scopes)

		return c.Next()
	}
}

// RequireRoles creates middleware that requires specific roles
func RequireRoles(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userRoles, ok := c.Locals("roles").([]string)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied",
			})
		}

		for _, required := range roles {
			for _, userRole := range userRoles {
				if userRole == required {
					return c.Next()
				}
			}
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Insufficient permissions",
		})
	}
}

// RequirePermissions creates middleware that requires specific permissions
func RequirePermissions(permissions ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		userPerms, ok := c.Locals("permissions").([]string)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied",
			})
		}

		for _, required := range permissions {
			found := false
			for _, userPerm := range userPerms {
				if userPerm == required {
					found = true
					break
				}
			}
			if !found {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Insufficient permissions",
				})
			}
		}

		return c.Next()
	}
}

// RequireScopes creates middleware that requires specific scopes (for service auth)
func RequireScopes(scopes ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		clientScopes, ok := c.Locals("scopes").([]string)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied",
			})
		}

		for _, required := range scopes {
			found := false
			for _, scope := range clientScopes {
				if scope == required || scope == "*" {
					found = true
					break
				}
			}
			if !found {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "Insufficient scopes",
				})
			}
		}

		return c.Next()
	}
}

func extractToken(c *fiber.Ctx) string {
	auth := c.Get("Authorization")
	if len(auth) > 7 && strings.ToLower(auth[:7]) == "bearer " {
		return auth[7:]
	}
	return ""
}
