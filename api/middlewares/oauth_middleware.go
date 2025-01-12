package customemiddlewares

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/minisource/auth/config"
	"github.com/minisource/auth/constants"
	"github.com/minisource/auth/services"
	helper "github.com/minisource/common_go/http/helpers"
	"github.com/minisource/common_go/service_errors"
	client "github.com/ory/hydra-client-go"
)

func OAuthValidationMiddleware(cfg *config.Config) gin.HandlerFunc {
	var tokenService = services.NewOAuthService(cfg)

	return func(c *gin.Context) {
		var err error
		tokenInfo := &client.OAuth2TokenIntrospection{}
		auth := c.GetHeader(constants.AuthorizationHeaderKey)
		token := strings.Split(auth, " ")
		if auth == "" {
			err = &service_errors.ServiceError{EndUserMessage: service_errors.TokenRequired}
		} else {
			tokenInfo, err = tokenService.ValidateToken(token[1])
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, helper.GenerateBaseResponseWithError(
				nil, false, helper.AuthError, err,
			))
			return
		}

		c.Set("token_info", tokenInfo)

		c.Next()
	}
}
