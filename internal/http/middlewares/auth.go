package middlewares

import (
	"github.com/gofiber/fiber/v2"

	"boxen_dispatch/internal/entities"
)

// Protected checks if the request has a valid JWT
func Protected() fiber.Handler {
	return func(c *fiber.Ctx) error {
		sess, err := entities.Session.Get(c)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Unable to check for login"})
		}
		username := sess.Get("username")
		if username != nil {
			c.Locals("username", username)
			return c.Next()
		}
		return c.Status(fiber.StatusUnauthorized).Redirect("/login")
	}
}
