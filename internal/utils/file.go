package utils

import (
	"os"
)

func Exists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}
