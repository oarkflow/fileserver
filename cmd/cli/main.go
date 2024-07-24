package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"

	"boxen_dispatch/cmd/cli/commands"
	"boxen_dispatch/cmd/common"
	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/interfaces"
)

func Setup() {
	common.Execute()
	InitCli()
}

func InitCli() {
	cliCmd := entities.Config.GetString("cli.command")
	appName := entities.Config.GetString("app.name")

	entities.CliApp = &cli.App{
		Name:  cliCmd,
		Usage: fmt.Sprintf("Install and manage %s products", appName),
	}
	for _, cmd := range RegisteredCommands() {
		entities.CliApp.Commands = append(entities.CliApp.Commands, ToCliCommand(cmd))
	}
}

func Run() {
	Setup()
	err := entities.CliApp.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func RegisteredCommands() []interfaces.Command {
	return []interfaces.Command{
		&commands.SendEmailCommand{},
		&commands.SendSMSCommand{},
	}
}

func ToCliCommand(cmd interfaces.Command) *cli.Command {
	cliCmd := &cli.Command{
		Name:   cmd.Signature(),
		Usage:  cmd.Description(),
		Flags:  cmd.Flags(),
		Action: cmd.Handle,
	}

	subCmds := cmd.Subcommands()
	if len(subCmds) > 0 {
		cliCmd.Subcommands = make([]*cli.Command, len(subCmds))
		for i, subCmd := range subCmds {
			cliCmd.Subcommands[i] = ToCliCommand(subCmd)
		}
	}

	return cliCmd
}
