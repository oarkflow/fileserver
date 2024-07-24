package commands

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/interfaces"
)

type SendEmailCommand struct {
}

func (s SendEmailCommand) Signature() string {
	return "send:email"
}

func (s SendEmailCommand) Description() string {
	return "Sends Email"
}

func (s SendEmailCommand) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "to",
			Aliases:  []string{"t"},
			Usage:    "Email address of the recipient",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "subject",
			Aliases:  []string{"s"},
			Usage:    "Title of the email",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "template",
			Aliases:  []string{"tpl"},
			Usage:    "Path to the HTML template file",
			Required: true,
		},
	}
}

func (s SendEmailCommand) Handle(c *cli.Context) error {
	to := c.String("to")
	subject := c.String("subject")
	template := c.String("template")
	if to == "" {
		return errors.New("Target email address is required")
	}
	if subject == "" {
		return errors.New("Title for email is not provided")
	}
	if template == "" {
		return errors.New("Email template or format missing")
	}
	dir := entities.Config.GetString("app.view_path")
	tmplPath := filepath.Join(dir, "emails", template)
	emailFile, err := os.ReadFile(tmplPath)
	if err != nil {
		return err
	}
	err = entities.Dispatcher.Dispatch("email", interfaces.Payload{
		Message: string(emailFile),
		Target:  to,
		Title:   subject,
	})
	if err != nil {
		return err
	}

	fmt.Println("Email sent successfully!")
	return nil
}

func (s SendEmailCommand) Subcommands() []interfaces.Command {
	return []interfaces.Command{}
}
