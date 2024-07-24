package utils

import (
	"github.com/gofiber/fiber/v2"
)

func GetCSRFToken(ctx *fiber.Ctx) string {
	return ctx.Cookies("csrf_")
}
