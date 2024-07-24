package middlewares

import (
	"os"

	"github.com/gofiber/fiber/v2"
)

func SecureHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Prevents clickjacking
		c.Set("X-Frame-Options", "DENY")

		// Helps prevent XSS attacks
		c.Set("X-XSS-Protection", "1; mode=block")

		// Strict-Transport-Security: force HTTPS for the next year including subdomains
		if os.Getenv("APP_ENV") == "production" && c.Protocol() == "https" {
			c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		// Content Security Policy: Define loading policy for all resources type
		c.Set("Content-Security-Policy", "default-src gap://ready file://* *; img-src 'self' http://* https://* data:; style-src 'self' http://* https://* 'unsafe-inline'; script-src 'self' http://* https://* 'unsafe-inline' 'unsafe-eval'")

		// Prevent MIME type sniffing vulnerabilities
		c.Set("X-Content-Type-Options", "nosniff")

		// Move to next middleware
		return c.Next()
	}
}
