package routers

import (
	"github.com/gin-gonic/gin"
	"github.com/minisource/auth/api/handlers"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/http/middlewares"
)

func User(router *gin.RouterGroup, cfg *config.Config) {
	h := handlers.NewUsersHandler(cfg)

	router.POST("/send-otp", middlewares.OtpLimiter((*middlewares.OtpConfig)(&cfg.Otp)), h.SendOtp)
	router.POST("/login-by-username", h.LoginByUsername)
	router.POST("/register-by-username", h.RegisterByUsername)
	router.POST("/login-by-mobile", h.RegisterLoginByMobileNumber)
}
