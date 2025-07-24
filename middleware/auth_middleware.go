package middleware

import (
	"fmt"
	"strings"

	"github.com/casdoor/casdoor-go-sdk/casdoorsdk"
	"github.com/gofiber/fiber/v2"
	auth "github.com/minisource/auth/service"
	"github.com/minisource/common_go/constants"
	"github.com/minisource/common_go/http/helper"
	"github.com/minisource/common_go/service_errors"
)

func Authentication(service *auth.AuthService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var err error
		var claimMap *casdoorsdk.IntrospectTokenResult
		auth := c.Get(constants.AuthorizationHeaderKey)
		token := strings.Split(auth, " ")
		if auth == "" || len(token) < 2 {
			err = &service_errors.ServiceError{EndUserMessage: service_errors.TokenRequired}
		} else {
			claimMap, err = service.ValidateToken(token[1])
			if err != nil {
				return err
			}
		}
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(
				helper.GenerateBaseResponseWithError(nil, false, helper.AuthError, err),
			)
		}

		// Check if the token is active
		if !claimMap.Active {
			return c.Status(fiber.StatusUnauthorized).JSON(
				helper.GenerateBaseResponseWithError(nil, false, helper.AuthError, &service_errors.ServiceError{
					EndUserMessage: service_errors.UserDisabled,
				}),
			)
		}

		c.Set(constants.ClientIdKey, claimMap.ClientId)
		if username := claimMap.Username; username != "" {
			c.Set(constants.UsernameKey, username)
		}
		if expire := claimMap.Exp; expire != 0 {
			c.Set(constants.ExpireTimeKey, fmt.Sprintf("%d", expire))
		}

		return c.Next()
	}
}
