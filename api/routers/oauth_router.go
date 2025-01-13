package routers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/handlers"
	"github.com/minisource/auth/config"
)

func OAuthRouter(r fiber.Router, cfg *config.Config) {
	h := handlers.NewOAuthHandler(cfg)

	r.Post("/", h.Create)
	r.Get("/", h.GetAll)
	r.Get("/:id", h.GetById)
	r.Delete("/:id", h.Delete)
	r.Post("/GenerateToken", h.GenerateToken)
	r.Post("/ValidateToken", h.ValidateToken)
}
