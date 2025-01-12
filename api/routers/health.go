package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/minisource/auth/api/handlers"
)

func Health(r *gin.RouterGroup) {
	handler := handlers.NewHealthHandler()

	r.GET("/", handler.Health)
}
