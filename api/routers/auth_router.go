package routers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/handlers"
	"github.com/minisource/auth/config"
	"github.com/minisource/common_go/http/middleware"
)

func Authentication(router fiber.Router, cfg *config.Config) {
	h := handlers.NewAuthHandler(cfg)

	router.Post("/send-otp", middleware.OtpLimiter((*middleware.OtpConfig)(&cfg.Otp)), h.SendOtp)
	// router.Post("/verify-otp", h.VerifyOtp) // TODO: uncomment after implement verify
}
