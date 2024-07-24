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
	HOST  string
	PORT  string
	PATHS []string
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
		HOST = c.String("ip")
		PORT = c.String("port")

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
		app := fiber.New(fiber.Config{
			Views: engine,
		})
		app.Use(func(c *fiber.Ctx) error {
			dir := c.Query("dir")
			if dir != "" && !checkPath(PATHS, dir) {
				return c.Redirect("/")
			}
			return c.Next()
		})
		setupRoutes(app)

		url := fmt.Sprintf("%s:%s", HOST, PORT)
		log.Printf("\nServing on: http://%s\n", url)
		if !isSudo() {
			_ = browser.OpenURL("http://" + url)
		}
		err := app.Listen(url)
		log.Fatal(err)
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
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
		return c.Redirect("/view?dir="+PATHS[0], fiber.StatusFound)
	}
	return dashboard(c)
}

func dashboard(c *fiber.Ctx) error {
	var f AllFiles
	for _, dir := range PATHS {
		dir = filepath.Clean(dir)
		if dir == "" {
			return c.Redirect("/", fiber.StatusFound)
		}
		dir = filepath.ToSlash(dir)
		parent := filepath.Dir(dir)
		if parent == "." {
			parent = "/"
		}
		if strings.Contains(dir, "..") {
			return c.Redirect("/", fiber.StatusFound)
		}
		path := filepath.Clean(dir) // Use the directory path from the query
		if !exists(path) {
			return c.Status(fiber.StatusNotFound).SendString("File Not Found")
		}
		entry, err := os.Stat(path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := strings.TrimPrefix(path, "/")
			size := humanSize(entry.Size())
			mode := fmt.Sprintf("%v", entry.Mode())
			date := fmt.Sprintf("%v", entry.ModTime().Format(time.RFC822))

			file := File{Name: name, Size: size, Mode: mode, Date: date}
			d := Dir{File: file, IsDir: true}
			f.Dirs = append(f.Dirs, d)
		}
	}

	title := "Directory listing for multiple paths"
	context := Context{Title: title, Files: f.Files, Dirs: f.Dirs, Images: f.Images}
	return c.Render("home-page", context)
}

func getFile(c *fiber.Ctx) error {
	file := c.Query("file")
	if file == "" {
		return c.Redirect("/", fiber.StatusFound)
	}
	path := filepath.Clean(file) // Directly use the file path
	if !exists(path) {
		return c.Status(fiber.StatusNotFound).SendString("File Not Found")
	}
	filename := filepath.Base(path)
	c.Set("Content-Disposition", "attachment; filename="+filename)
	return c.SendFile(path)
}

func uploadFiles(c *fiber.Ctx) error {
	form, err := c.MultipartForm()
	if err != nil {
		return err
	}
	files := form.File["file-upload"]
	dir := filepath.Clean(c.FormValue("directory"))
	if strings.Contains(dir, "..") {
		return c.Redirect("/", fiber.StatusFound)
	}
	for _, file := range files {
		path := filepath.Clean(filepath.Join(dir, file.Filename)) // Use the directory path from the form
		src, err := file.Open()
		if err != nil {
			return err
		}
		defer src.Close()
		if err := copyUploadFile(path, src); err != nil {
			return err
		}
	}
	return c.Redirect("/view?dir="+dir, fiber.StatusFound)
}

func deleteFile(c *fiber.Ctx) error {
	filename := c.FormValue("filename")
	if filename == "" {
		return c.Status(fiber.StatusInternalServerError).SendString("missing form value")
	}
	if strings.Contains(filename, "..") {
		return c.Redirect("/", fiber.StatusFound)
	}
	dir := c.FormValue("directory")
	path := filepath.Clean(filepath.Join(dir, filename)) // Use the directory path from the form
	if !exists(path) {
		return c.Status(fiber.StatusInternalServerError).SendString("File not found")
	}
	_ = os.Remove(path)
	return c.Redirect("/view?dir="+dir, fiber.StatusFound)
}

func viewDir(c *fiber.Ctx) error {
	dir := filepath.Clean(c.Query("dir"))
	if dir == "" {
		return c.Redirect("/", fiber.StatusFound)
	}
	dir = filepath.ToSlash(dir)
	parent := filepath.Dir(dir)
	if parent == "." {
		parent = "/"
	}
	if strings.Contains(dir, "..") {
		return c.Redirect("/", fiber.StatusFound)
	}
	path := filepath.Clean(dir) // Use the directory path from the query
	if !exists(path) {
		return c.Status(fiber.StatusNotFound).SendString("File Not Found")
	}
	f, err := fileFunc(path)
	if err != nil {
		return err
	}
	title := "Directory listing for " + dir
	context := Context{Title: title, Directory: dir, Parent: parent, Files: f.Files, Dirs: f.Dirs, Images: f.Images}
	return c.Render("index", context)
}

func checkDir(dir string) error {
	stat, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func copyUploadFile(path string, src multipart.File) error {
	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

func fileFunc(dir string) (AllFiles, error) {
	var a AllFiles
	files, err := os.ReadDir(dir)
	if err != nil {
		return a, err
	}
	for _, entry := range files {
		fi, _ := entry.Info()
		name := entry.Name()
		size := humanSize(fi.Size())
		mode := fmt.Sprintf("%v", fi.Mode())
		date := fmt.Sprintf("%v", fi.ModTime().Format(time.RFC822))

		f := File{Name: name, Size: size, Mode: mode, Date: date}

		if isImage(name) {
			img := Image{File: f}
			a.Images = append(a.Images, img)
		} else if fi.IsDir() {
			d := Dir{File: f, IsDir: true}
			a.Dirs = append(a.Dirs, d)
		} else {
			a.Files = append(a.Files, f)
		}
	}
	return a, nil
}

func isImage(fn string) bool {
	ext := strings.ToLower(filepath.Ext(fn))
	for _, imgType := range imageTypes {
		if ext == imgType {
			return true
		}
	}
	return false
}

func humanSize(s int64) string {
	if s == 0 {
		return "0"
	}
	sizes := []string{"B", "K", "M", "G"}
	i := math.Floor(math.Log(float64(s)) / math.Log(1024))
	human := float64(s) / math.Pow(1024, i)
	return fmt.Sprintf("%0.1f %s", human, sizes[int(i)])
}

func isSudo() bool {
	return os.Geteuid() == 0
}

func checkPath(baseDirs []string, path string) bool {
	path = filepath.Clean(path)
	for _, baseDir := range baseDirs {
		baseDir = filepath.Clean(baseDir)
		if strings.HasPrefix(path, baseDir) {
			relPath, err := filepath.Rel(baseDir, path)
			if err != nil {
				continue
			}
			if !strings.Contains(relPath, "..") {
				return true
			}
		}
	}
	return false
}
