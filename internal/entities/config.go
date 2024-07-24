package entities

import (
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/urfave/cli/v2"
	"gorm.io/gorm"

	"boxen_dispatch/internal/interfaces"
)

var (
	CliApp    *cli.App
	Config    interfaces.Config
	DB        *gorm.DB
	Session   *session.Store
	Workspace interfaces.FS
)
