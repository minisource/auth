package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/minisource/auth/api/handlers"
	"github.com/minisource/auth/config"
)

func OAuthRouter(r *gin.RouterGroup, cfg *config.Config) {
	h := handlers.NewOAuthHandler(cfg)

	r.POST("/", h.Create)
	r.GET("/", h.GetAll)
	r.GET("/:id", h.GetById)
	r.DELETE("/:id", h.Delete)
	r.POST("/GenerateToken", h.GenerateToken)
	r.POST("/ValidateToken", h.ValidateToken)
}
