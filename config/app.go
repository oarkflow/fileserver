package config

import (
	"boxen_dispatch/internal/interfaces"
)

func AppConfig(config interfaces.Config) {
	config.Add("app", map[string]any{
		"key":              config.Env("APP_KEY", "OdR4DlWhZk6osDd0qXLdVT88lHOvj14K"),
		"name":             config.Env("APP_NAME", "Photo Booth v1.0"),
		"debug":            config.Env("APP_DEBUG", true),
		"url":              config.Env("APP_URL", "http://0.0.0.0:3003"),
		"host":             config.Env("APP_HOST", "0.0.0.0:3003"),
		"asset_compress":   config.Env("ASSET_COMPRESS", true),
		"enable_https":     config.Env("ENABLE_HTTPS", false),
		"storage_path":     config.Env("STORAGE_PATH", "storage"),
		"view_path":        config.Env("VIEW_PATH", "internal/views"),
		"view_extension":   config.Env("VIEW_EXTENSION", ".html"),
		"disable_plugins":  config.Env("DISABLE_PLUGINS", ""),
		"maintenance_mode": config.Env("MAINTENANCE_MODE", false),
	})

	config.Add("database", map[string]any{
		"name":          config.Env("DB_NAME", ""),
		"prefix":        config.Env("DB_PREFIX", "photo_booth"),
		"session_table": config.Env("SESSION_TABLE", "login_sessions"),
	})

	config.Add("cli", map[string]any{
		"command": config.Env("CLI_COMMAND", "cli"),
	})

	config.Add("booth", map[string]any{
		"file": config.Env("BOOTH_FILE", "booth.yaml"),
	})
}
