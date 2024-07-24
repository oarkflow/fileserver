package web

import (
	"embed"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/sqlite3"

	"boxen_dispatch/cmd/common"
	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/http/middlewares"
	"boxen_dispatch/internal/routes"
	"boxen_dispatch/internal/utils" // Import the utils package

	"github.com/cloudflare/tableflip"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/template/html/v2"
)

func setupServer(env string, fs, htmlFS embed.FS) *fiber.App {
	// Values retrieved from config/app.go
	dir := entities.Config.GetString("app.view_path")
	extension := entities.Config.GetString("app.view_extension")
	appName := entities.Config.GetString("app.name")

	engine := html.New(utils.PathFromRoot(dir), extension)
	engine.ShouldReload = true
	app := fiber.New(fiber.Config{
		Immutable: true,
		AppName:   appName,
		Views:     engine,
	})
	setupStatic(app, fs)
	setupGlobalMiddleware(app, env)
	setupRoutes(app, env)
	return app
}

func setupStatic(app *fiber.App, fs embed.FS) {
	publicFS := http.FS(fs)
	app.Use("/css", filesystem.New(filesystem.Config{
		Root:       publicFS,
		PathPrefix: "public/css",
	}))
	app.Use("/js", filesystem.New(filesystem.Config{
		Root:       publicFS,
		PathPrefix: "public/js",
	}))
	app.Use("/images", filesystem.New(filesystem.Config{
		Root:       publicFS,
		PathPrefix: "public/images",
	}))
	app.Use("/favicon.ico", filesystem.New(filesystem.Config{
		Root:       publicFS,
		PathPrefix: "public/favicon.ico",
	}))
}

func setupRoutes(app *fiber.App, env string) {
	routes.Web(app, env)
	routes.Api(app, env)
}

func Execute(fs embed.FS, htmlFS embed.FS) {
	env := common.Execute()
	app := setupServer(env, fs, htmlFS)
	gracefulListen(app, env)
}

func setupGlobalMiddleware(app *fiber.App, env string) {
	// Middleware
	if !slices.Contains([]string{"test", "development"}, env) {
		app.Use(csrf.New(csrf.Config{
			KeyLookup:      "form:_csrf",
			CookieHTTPOnly: true,
			CookieSameSite: "Strict",
			Expiration:     600,
			SingleUseToken: true,
		}))
	}
	app.Use(cors.New())
	app.Use(logger.New())
	app.Use(recover.New())
	app.Use(middlewares.SecureHeaders())
	app.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 5 * 60 * 1000,
	}))
	storage := sqlite3.New(sqlite3.Config{Database: common.GetDBName(env), Table: entities.Config.GetString("database.session_table")})
	entities.Session = session.New(session.Config{CookieHTTPOnly: true, Storage: storage})
}

func gracefulListen(app *fiber.App, env string) {
	upg, err := tableflip.New(tableflip.Options{})
	if err != nil {
		log.Fatalf("Failed to initialize tableflip: %v", err)
	}
	defer upg.Stop()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGHUP)
		for range sig {
			log.Println("Received SIGHUP, performing upgrade")
			if err := upg.Upgrade(); err != nil {
				log.Printf("Upgrade failed: %v", err)
			}
		}
	}()
	host := entities.Config.GetString("app.host")
	ln, err := upg.Fds.Listen("tcp", host)
	if err != nil {
		log.Fatalf("Failed to listen on :%s: %v", host, err)
	}
	defer ln.Close()

	// Log the port and environment
	log.Printf("Server is starting on http://%s in %s mode", host, env)
	go func() {
		if err := app.Listener(ln); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	if err := upg.Ready(); err != nil {
		log.Fatalf("Failed to signal readiness: %v", err)
	}

	<-upg.Exit()
	log.Println("Exiting...")
}
