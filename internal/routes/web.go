package routes

import (
	"github.com/gofiber/fiber/v2"

	"boxen_dispatch/internal/http/controllers"
)

func Web(app fiber.Router, env string) {
	if env == "test" {
		app.Get("/test-panic", controllers.Home.Test)
	}
	// Unprotected routes
	LandingRoutes(app)
}

func LandingRoutes(app fiber.Router) {
	app.Get("/", controllers.Home.Index)
	app.Get("/ping", controllers.Home.Ping)
	app.Get("/view", controllers.Home.View)
	app.Get("/get", controllers.Home.Get)
}
