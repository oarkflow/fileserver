package controllers

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/models"
	"boxen_dispatch/internal/utils"
)

type HomeController struct {
}

func (h *HomeController) Ping(c *fiber.Ctx) error {
	return c.SendString("pong")
}

func (h *HomeController) Test(c *fiber.Ctx) error {
	panic("intentional panic for testing")
}

func (h *HomeController) Get(c *fiber.Ctx) error {
	file := filepath.Clean(c.Query("file"))
	if file == "" || !utils.Exists(file) {
		return c.Redirect("/", fiber.StatusFound)
	}
	c.Set("Content-Disposition", "attachment; filename="+filepath.Base(file))
	return c.SendFile(file)
}

func (h *HomeController) View(c *fiber.Ctx) error {
	dir := filepath.Clean(c.Query("dir"))
	if dir == "" || strings.Contains(dir, "..") || !utils.Exists(dir) {
		return c.Redirect("/", fiber.StatusFound)
	}
	allFiles, err := getAllFiles(dir)
	if err != nil {
		return err
	}
	context := fiber.Map{
		"Title":     "Directory listing for " + dir,
		"Directory": dir,
		"Parent":    filepath.Dir(dir),
		"Files":     allFiles.Files,
		"Dirs":      allFiles.Dirs,
		"Images":    allFiles.Images,
	}
	return c.Render("index", context, "layout")
}

func (h *HomeController) Index(ctx *fiber.Ctx) error {
	var dirs []models.Dir
	for _, dir := range entities.Workspace.Paths() {
		dir = filepath.Clean(dir)
		if dir == "" || strings.Contains(dir, "..") || !utils.Exists(dir) {
			return ctx.Redirect("/", fiber.StatusFound)
		}
		entry, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			dirs = append(dirs, models.Dir{
				File: models.File{
					Name: filepath.ToSlash(strings.TrimPrefix(dir, "/")),
					Size: utils.HumanSize(entry.Size()),
					Mode: fmt.Sprintf("%v", entry.Mode()),
					Date: entry.ModTime().Format(time.RFC822),
				},
				IsDir: true,
			})
		}
	}
	return ctx.Render("home-page", fiber.Map{
		"Title": "Directory listing for multiple paths",
		"Dirs":  dirs,
	}, "layout")
}

func NewHomeController() *HomeController {
	return &HomeController{}
}

func getAllFiles(dir string) (models.AllFiles, error) {
	var allFiles models.AllFiles
	files, err := os.ReadDir(dir)
	if err != nil {
		return allFiles, err
	}
	for _, entry := range files {
		fi, _ := entry.Info()
		file := models.File{
			Name: entry.Name(),
			Size: utils.HumanSize(fi.Size()),
			Mode: fmt.Sprintf("%v", fi.Mode()),
			Date: fi.ModTime().Format(time.RFC822),
		}
		if utils.IsImage(entry.Name()) {
			allFiles.Images = append(allFiles.Images, models.Image{File: file})
		} else if fi.IsDir() {
			allFiles.Dirs = append(allFiles.Dirs, models.Dir{File: file, IsDir: true})
		} else {
			allFiles.Files = append(allFiles.Files, file)
		}
	}
	return allFiles, nil
}
