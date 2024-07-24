package routes

import (
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v2"

	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/http/controllers"
)

func Web(app fiber.Router, env string) {
	if env == "test" {
		app.Get("/test-panic", controllers.Home.Test)
	}
	app.Use(redirectInvalidDir)
	// Unprotected routes
	LandingRoutes(app)
}

func LandingRoutes(app fiber.Router) {
	app.Get("/", controllers.Home.Index)
	app.Get("/ping", controllers.Home.Ping)
	app.Get("/view", controllers.Home.View)
	app.Get("/get", controllers.Home.Get)
}

func redirectInvalidDir(c *fiber.Ctx) error {
	dir := c.Query("dir")
	if dir != "" && !checkPath(entities.Workspace.Paths(), dir) {
		return c.Redirect("/")
	}
	return c.Next()
}

func checkPath(baseDirs []string, path string) bool {
	path = filepath.Clean(path)
	for _, baseDir := range baseDirs {
		baseDir = filepath.Clean(baseDir)
		if strings.HasPrefix(path, baseDir) {
			if relPath, err := filepath.Rel(baseDir, path); err == nil && !strings.Contains(relPath, "..") {
				return true
			}
		}
	}
	return false
}
