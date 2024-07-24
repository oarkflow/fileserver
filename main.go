package main

import (
	"embed"

	"boxen_dispatch/cmd/web"
)

//go:embed public/*
var publicDir embed.FS

//go:embed internal/views/*
var embedHtmlDir embed.FS

func main() {
	web.Execute(publicDir, embedHtmlDir)
}
