package commands

import (
	"errors"
	"fmt"

	"github.com/urfave/cli/v2"

	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/interfaces"
)

type SendSMSCommand struct {
}

func (s SendSMSCommand) Signature() string {
	return "send:sms"
}

func (s SendSMSCommand) Description() string {
	return "Sends SMS"
}

func (s SendSMSCommand) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:     "to",
			Aliases:  []string{"t"},
			Usage:    "Phone number of the recipient",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "message",
			Aliases:  []string{"m"},
			Usage:    "SMS content",
			Required: true,
		},
	}
}

func (s SendSMSCommand) Handle(c *cli.Context) error {
	to := c.String("to")
	message := c.String("message")
	if to == "" {
		return errors.New("Target phone is required")
	}
	if message == "" {
		return errors.New("message for SMS is not provided")
	}
	err := entities.Dispatcher.Dispatch("sms", interfaces.Payload{
		Message: message,
		Target:  to,
	})
	if err != nil {
		return err
	}

	fmt.Println("SMS sent successfully!")
	return nil
}

func (s SendSMSCommand) Subcommands() []interfaces.Command {
	return []interfaces.Command{}
}
