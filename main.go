package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/oarkflow/browser"
	"github.com/urfave/cli/v2"
)

const Version = "fs server 0.1.7"

type File struct {
	Name string
	Size string
	Mode string
	Date string
}

type Image struct {
	File
}

type Dir struct {
	File
	IsDir bool
}

type AllFiles struct {
	Files  []File
	Images []Image
	Dirs   []Dir
}

type Context struct {
	Title     string
	Directory string
	Parent    string
	Files     []File
	Images    []Image
	Dirs      []Dir
}

var (
	HOST, PORT string
	PATHS      []string
)

var imageTypes = []string{".png", ".jpg", "jpeg", ".gif"}

func main() {
	app := cli.NewApp()
	app.Name = "fs"
	app.Usage = "Serve the given folder via an HTTP server"
	app.Version = Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "ip", Aliases: []string{"i"}, Value: "0.0.0.0", Usage: "IP address to serve on"},
		&cli.StringFlag{Name: "port", Aliases: []string{"p"}, Value: "8080", Usage: "Port to listen on"},
	}

	app.Action = func(c *cli.Context) error {
		HOST, PORT = c.String("ip"), c.String("port")

		if c.NArg() == 0 {
			cli.ShowAppHelpAndExit(c, 1)
		}

		PATHS = c.Args().Slice()
		for _, path := range PATHS {
			if err := checkDir(path); err != nil {
				log.Fatalf("%v", err)
			}
		}
		engine := html.New("./views", ".html")
		engine.ShouldReload = true
		app := fiber.New(fiber.Config{
			Views: engine,
		})
		app.Use(redirectInvalidDir)
		setupRoutes(app)

		url := fmt.Sprintf("%s:%s", HOST, PORT)
		log.Printf("\nServing on: http://%s\n", url)
		if !isSudo() {
			_ = browser.OpenURL("http://" + url)
		}
		log.Fatal(app.Listen(url))
		return nil
	}

	log.Fatal(app.Run(os.Args))
}

func setupRoutes(app *fiber.App) {
	app.Get("/", redirectRoot)
	app.Get("/get", getFile)
	app.Post("/upload", uploadFiles)
	app.Get("/view", viewDir)
	app.Post("/delete", deleteFile)
}

func redirectRoot(c *fiber.Ctx) error {
	if len(PATHS) == 1 {
		return c.Redirect("/view?dir=" + PATHS[0])
	}
	return dashboard(c)
}

func dashboard(c *fiber.Ctx) error {
	var allFiles AllFiles
	for _, dir := range PATHS {
		dir = filepath.Clean(dir)
		if dir == "" || strings.Contains(dir, "..") || !exists(dir) {
			return c.Redirect("/", fiber.StatusFound)
		}
		entry, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			allFiles.Dirs = append(allFiles.Dirs, Dir{
				File: File{
					Name: filepath.ToSlash(strings.TrimPrefix(dir, "/")),
					Size: humanSize(entry.Size()),
					Mode: fmt.Sprintf("%v", entry.Mode()),
					Date: entry.ModTime().Format(time.RFC822),
				},
				IsDir: true,
			})
		}
	}

	context := Context{
		Title: "Directory listing for multiple paths",
		Dirs:  allFiles.Dirs,
	}
	return c.Render("home-page", context)
}

func getFile(c *fiber.Ctx) error {
	file := filepath.Clean(c.Query("file"))
	if file == "" || !exists(file) {
		return c.Redirect("/", fiber.StatusFound)
	}
	c.Set("Content-Disposition", "attachment; filename="+filepath.Base(file))
	return c.SendFile(file)
}

func uploadFiles(c *fiber.Ctx) error {
	form, err := c.MultipartForm()
	if err != nil {
		return err
	}
	dir := filepath.Clean(c.FormValue("directory"))
	if strings.Contains(dir, "..") {
		return c.Redirect("/", fiber.StatusFound)
	}
	for _, file := range form.File["file-upload"] {
		if err := saveUploadedFile(filepath.Join(dir, file.Filename), file); err != nil {
			return err
		}
	}
	return c.Redirect("/view?dir=" + dir)
}

func deleteFile(c *fiber.Ctx) error {
	filename := filepath.Join(filepath.Clean(c.FormValue("directory")), c.FormValue("filename"))
	if filename == "" || strings.Contains(filename, "..") || !exists(filename) {
		return c.Status(fiber.StatusInternalServerError).SendString("File not found")
	}
	os.Remove(filename)
	return c.Redirect("/view?dir=" + filepath.Dir(filename))
}

func viewDir(c *fiber.Ctx) error {
	dir := filepath.Clean(c.Query("dir"))
	if dir == "" || strings.Contains(dir, "..") || !exists(dir) {
		return c.Redirect("/", fiber.StatusFound)
	}
	allFiles, err := getAllFiles(dir)
	if err != nil {
		return err
	}
	context := Context{
		Title:     "Directory listing for " + dir,
		Directory: dir,
		Parent:    filepath.Dir(dir),
		Files:     allFiles.Files,
		Dirs:      allFiles.Dirs,
		Images:    allFiles.Images,
	}
	return c.Render("index", context)
}

func checkDir(dir string) error {
	stat, err := os.Stat(dir)
	if err != nil || !stat.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func saveUploadedFile(path string, file *multipart.FileHeader) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

func getAllFiles(dir string) (AllFiles, error) {
	var allFiles AllFiles
	files, err := os.ReadDir(dir)
	if err != nil {
		return allFiles, err
	}
	for _, entry := range files {
		fi, _ := entry.Info()
		file := File{
			Name: entry.Name(),
			Size: humanSize(fi.Size()),
			Mode: fmt.Sprintf("%v", fi.Mode()),
			Date: fi.ModTime().Format(time.RFC822),
		}
		if isImage(entry.Name()) {
			allFiles.Images = append(allFiles.Images, Image{File: file})
		} else if fi.IsDir() {
			allFiles.Dirs = append(allFiles.Dirs, Dir{File: file, IsDir: true})
		} else {
			allFiles.Files = append(allFiles.Files, file)
		}
	}
	return allFiles, nil
}

func isImage(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, imgType := range imageTypes {
		if ext == imgType {
			return true
		}
	}
	return false
}

func humanSize(size int64) string {
	if size == 0 {
		return "0"
	}
	sizes := []string{"B", "K", "M", "G"}
	i := int(math.Floor(math.Log(float64(size)) / math.Log(1024)))
	return fmt.Sprintf("%.1f %s", float64(size)/math.Pow(1024, float64(i)), sizes[i])
}

func isSudo() bool {
	return os.Geteuid() == 0
}

func redirectInvalidDir(c *fiber.Ctx) error {
	dir := c.Query("dir")
	if dir != "" && !checkPath(PATHS, dir) {
		return c.Redirect("/")
	}
	return c.Next()
}

func checkPath(baseDirs []string, path string) bool {
	path = filepath.Clean(path)
	for _, baseDir := range baseDirs {
		baseDir = filepath.Clean(baseDir)
		if strings.HasPrefix(path, baseDir) {
			if relPath, err := filepath.Rel(baseDir, path); err == nil && !strings.Contains(relPath, "..") {
				return true
			}
		}
	}
	return false
}
