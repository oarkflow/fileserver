package interfaces

import "github.com/urfave/cli/v2"

type Command interface {
	Signature() string
	Description() string
	Flags() []cli.Flag
	Handle(c *cli.Context) error
	Subcommands() []Command
}
