package config

import (
	"log"
	"os"

	"github.com/spf13/cast"
	"github.com/spf13/viper"

	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/utils"
)

func Load() string {
	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "development"
	}
	envFile := utils.PathFromRoot(".env." + env)
	entities.Config = New(envFile)
	AppConfig(entities.Config)
	return env
}

type Config struct {
	vip *viper.Viper
}

func New(envPath string) *Config {
	app := &Config{}
	app.vip = viper.New()
	app.vip.AutomaticEnv()

	if utils.Exists(envPath) {
		app.vip.SetConfigType("env")
		app.vip.SetConfigFile(envPath)

		if err := app.vip.ReadInConfig(); err != nil {
			log.Println("Invalid Config error: " + err.Error())
			os.Exit(0)
		}
	}
	return app
}

// Env Get config from env.
func (app *Config) Env(envName string, defaultValue ...any) any {
	value := app.Get(envName, defaultValue...)
	if cast.ToString(value) == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}

		return nil
	}

	return value
}

// Add config to application.
func (app *Config) Add(name string, configuration any) {
	app.vip.Set(name, configuration)
}

// Get config from application.
func (app *Config) Get(path string, defaultValue ...any) any {
	if !app.vip.IsSet(path) {
		if len(defaultValue) > 0 {
			return defaultValue[0]
		}
		return nil
	}

	return app.vip.Get(path)
}

// GetString Get string type config from application.
func (app *Config) GetString(path string, defaultValue ...any) string {
	value := cast.ToString(app.Get(path, defaultValue...))
	if value == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0].(string)
		}

		return ""
	}

	return value
}

// GetInt Get int type config from application.
func (app *Config) GetInt(path string, defaultValue ...any) int {
	value := app.Get(path, defaultValue...)
	if cast.ToString(value) == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0].(int)
		}

		return 0
	}

	return cast.ToInt(value)
}

// GetBool Get bool type config from application.
func (app *Config) GetBool(path string, defaultValue ...any) bool {
	value := app.Get(path, defaultValue...)
	if cast.ToString(value) == "" {
		if len(defaultValue) > 0 {
			return defaultValue[0].(bool)
		}

		return false
	}

	return cast.ToBool(value)
}
