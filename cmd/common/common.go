package common

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"boxen_dispatch/config"
	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/services/booth"
)

func Execute() string {
	env := config.Load()
	createDirectories("")
	// Initialize the database
	err := SetupDB(env)
	if err != nil {
		log.Fatalf("Unable to connect db. Error: %v", err)
	}
	booth.Init()
	return env
}

// SetupDB Setup Sqlite DB
func SetupDB(env string) error {
	var err error
	databasePath := GetDBName(env)
	entities.DB, err = gorm.Open(sqlite.Open(databasePath), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w on path %s", err, databasePath)
	}

	return nil
}

func GetDBName(env string) string {
	dbName := entities.Config.GetString("database.name")
	prefix := entities.Config.GetString("database.prefix")
	if dbName == "" {
		dbName = env
	}
	dbName = fmt.Sprintf("%s_%s.db", prefix, dbName)
	storagePath := entities.Config.GetString("app.storage_path")
	return filepath.Join(storagePath, dbName)
}

func createDirectories(dirs ...string) {
	for _, dir := range dirs {
		dir = filepath.Join(entities.Config.GetString("app.storage_path"), dir)
		createDirectory(dir)
	}
}

func createDirectory(dir string) {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, os.ModePerm)
	}
}
