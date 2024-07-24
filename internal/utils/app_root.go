package utils

import (
	"log"
	"path/filepath"
	"runtime"
)

// AppRoot stores the root directory of the application
var AppRoot string

func init() {
	_, b, _, _ := runtime.Caller(0)
	basePath := filepath.Dir(b)
	appRoot := filepath.Join(basePath, "../../")
	absAppRoot, err := filepath.Abs(appRoot)
	if err != nil {
		log.Fatalf("Failed to determine app root: %v", err)
	}
	AppRoot = absAppRoot
}

// PathFromRoot constructs a path relative to the application root
func PathFromRoot(relativePath string) string {
	return filepath.Join(AppRoot, relativePath)
}
