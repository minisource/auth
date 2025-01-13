package routers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/minisource/auth/api/handlers"
)

func Health(r fiber.Router) {
	handler := handlers.NewHealthHandler()

	r.Get("/", handler.Health)
}
