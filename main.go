package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/template/html/v2"
	"github.com/oarkflow/browser"
	"github.com/urfave/cli/v2"
)

const Version = "fs server 0.2.0"

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
	BaseIndex int
	BasePath  string
	Directory string
	Parent    string
	Files     []File
	Images    []Image
	Dirs      []Dir
}

type DashboardContext struct {
	Title string
	Bases []DashboardItem
}
type DashboardItem struct {
	Index int
	Path  string
}

var BaseDirs []string

var imageTypes = []string{".png", ".jpg", ".jpeg", ".gif", ".svg"}

func main() {
	appCLI := cli.NewApp()
	appCLI.Name = "fs"
	appCLI.Usage = "Serve one or more folders via an HTTP file manager"
	appCLI.Version = Version
	appCLI.Flags = []cli.Flag{
		&cli.StringFlag{Name: "ip", Aliases: []string{"i"}, Value: "0.0.0.0", Usage: "IP address to serve on"},
		&cli.StringFlag{Name: "port", Aliases: []string{"p"}, Value: "8080", Usage: "Port to listen on"},
	}
	appCLI.Action = func(c *cli.Context) error {
		ip, port := c.String("ip"), c.String("port")
		if c.NArg() == 0 {
			cli.ShowAppHelpAndExit(c, 1)
		}
		args := c.Args().Slice()
		for _, p := range args {
			abs, err := filepath.Abs(p)
			if err != nil {
				log.Fatalf("Error resolving path %s: %v", p, err)
			}
			if err := checkDir(abs); err != nil {
				log.Fatalf("%v", err)
			}
			BaseDirs = append(BaseDirs, abs)
		}
		engine := html.New("./views", ".html")
		engine.AddFuncMap(map[string]any{
			"lower": strings.ToLower,
			"split": strings.Split,
		})
		engine.Reload(true)
		app := fiber.New(fiber.Config{
			Views: engine,
		})
		app.Use(cors.New())
		app.Static("/static", "./static", fiber.Static{
			Compress:  true,
			ByteRange: true,
		})
		app.Static("/webfonts", "./webfonts", fiber.Static{
			Compress:  true,
			ByteRange: true,
		})
		setupRoutes(app)
		url := fmt.Sprintf("%s:%s", ip, port)
		log.Printf("\nServing on: http://%s\n", url)
		if !isSudo() {
			_ = browser.OpenURL("http://" + url)
		}
		log.Fatal(app.Listen(url))
		return nil
	}
	log.Fatal(appCLI.Run(os.Args))
}

func setupRoutes(app *fiber.App) {
	app.Get("/", dashboard)
	app.Get("/view", viewDir)
	app.Get("/get", getFile)
	app.Post("/upload", uploadFiles)
	app.Post("/delete", deleteFile)
	app.Post("/rename", renameItem)
	app.Post("/mkdir", makeDir)
	app.Get("/edit", editFile)
	app.Post("/save", saveFile)
}

func dashboard(c *fiber.Ctx) error {
	if len(BaseDirs) == 1 {
		return c.Redirect(fmt.Sprintf("/view?base=0"))
	}
	var items []DashboardItem
	for i, base := range BaseDirs {
		items = append(items, DashboardItem{Index: i, Path: base})
	}
	ctx := DashboardContext{
		Title: "Shared Directories",
		Bases: items,
	}
	return c.Render("dashboard", ctx)
}

func viewDir(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	dirParam := c.Query("dir", "")
	basePath := BaseDirs[baseIndex]
	fullPath := filepath.Join(basePath, dirParam)
	if !isSubPath(fullPath, basePath) {
		return c.Status(fiber.StatusForbidden).SendString("Access Denied")
	}
	allFiles, err := getAllFiles(fullPath)
	if err != nil {
		return err
	}
	parent := ""
	if dirParam != "" {
		parent = filepath.Dir(dirParam)
		if parent == "." {
			parent = ""
		}
	}
	ctx := Context{
		Title:     "Directory listing for " + fullPath,
		BaseIndex: baseIndex,
		BasePath:  basePath,
		Directory: dirParam,
		Parent:    parent,
		Files:     allFiles.Files,
		Dirs:      allFiles.Dirs,
		Images:    allFiles.Images,
	}
	return c.Render("index", ctx)
}

func getFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	basePath := BaseDirs[baseIndex]
	fullPath := filepath.Join(basePath, fileParam)
	if !isSubPath(fullPath, basePath) || !exists(fullPath) {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	return c.SendFile(fullPath)
}

func uploadFiles(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	basePath := BaseDirs[baseIndex]
	targetDir := filepath.Join(basePath, dirParam)
	if !isSubPath(targetDir, basePath) {
		return c.Status(fiber.StatusForbidden).SendString("Access Denied")
	}
	form, err := c.MultipartForm()
	if err != nil {
		return err
	}
	for _, file := range form.File["file-upload"] {
		relativePath := file.Filename
		targetPath := filepath.Join(targetDir, relativePath)
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return err
		}
		if !isSubPath(targetPath, basePath) {
			continue
		}
		if err := saveUploadedFile(targetPath, file); err != nil {
			return err
		}
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, dirParam))
}

func deleteFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	pathParam := c.FormValue("path")
	basePath := BaseDirs[baseIndex]
	fullPath := filepath.Join(basePath, pathParam)
	if !isSubPath(fullPath, basePath) || !exists(fullPath) {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	fi, err := os.Stat(fullPath)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		err = os.RemoveAll(fullPath)
	} else {
		err = os.Remove(fullPath)
	}
	if err != nil {
		return err
	}
	parent := filepath.Dir(pathParam)
	if parent == "." {
		parent = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, parent))
}

func makeDir(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	newDirName := c.FormValue("newDirName")
	if newDirName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Directory name required")
	}
	basePath := BaseDirs[baseIndex]
	targetDir := filepath.Join(basePath, dirParam, newDirName)
	if !isSubPath(targetDir, basePath) {
		return c.Status(fiber.StatusForbidden).SendString("Access Denied")
	}
	err = os.Mkdir(targetDir, 0755)
	if err != nil {
		return err
	}
	newRel := filepath.Join(dirParam, newDirName)
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, newRel))
}

func renameItem(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	oldPath := c.FormValue("oldPath")
	newName := c.FormValue("newName")
	if newName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("New name required")
	}
	basePath := BaseDirs[baseIndex]
	fullOldPath := filepath.Join(basePath, oldPath)
	newPath := filepath.Join(filepath.Dir(fullOldPath), newName)
	if !isSubPath(fullOldPath, basePath) || !isSubPath(newPath, basePath) {
		return c.Status(fiber.StatusForbidden).SendString("Access Denied")
	}
	err = os.Rename(fullOldPath, newPath)
	if err != nil {
		return err
	}
	parent := filepath.Dir(oldPath)
	if parent == "." {
		parent = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, parent))
}

func editFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	basePath := BaseDirs[baseIndex]
	fullPath := filepath.Join(basePath, fileParam)
	if !isSubPath(fullPath, basePath) || !exists(fullPath) {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	ext := strings.ToLower(filepath.Ext(fullPath))

	if ext != ".txt" && ext != ".md" && ext != ".go" && ext != ".html" {
		return c.Status(fiber.StatusBadRequest).SendString("Editing not supported for this file type")
	}
	content, err := os.ReadFile(fullPath)
	if err != nil {
		return err
	}
	data := fiber.Map{
		"Title":     "Edit File - " + fileParam,
		"BaseIndex": baseIndex,
		"File":      fileParam,
		"Content":   string(content),
	}
	return c.Render("edit", data)
}

func saveFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(BaseDirs) {
		return c.Redirect("/")
	}
	fileParam := c.FormValue("file")
	content := c.FormValue("content")
	basePath := BaseDirs[baseIndex]
	fullPath := filepath.Join(basePath, fileParam)
	if !isSubPath(fullPath, basePath) {
		return c.Status(fiber.StatusForbidden).SendString("Access Denied")
	}
	err = os.WriteFile(fullPath, []byte(content), 0644)
	if err != nil {
		return err
	}
	dirParam := filepath.Dir(fileParam)
	if dirParam == "." {
		dirParam = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, dirParam))
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
	entries, err := os.ReadDir(dir)
	if err != nil {
		return allFiles, err
	}
	for _, entry := range entries {
		info, _ := entry.Info()
		f := File{
			Name: entry.Name(),
			Size: humanSize(info.Size()),
			Mode: fmt.Sprintf("%v", info.Mode()),
			Date: info.ModTime().Format(time.RFC822),
		}
		if isImage(entry.Name()) {
			allFiles.Images = append(allFiles.Images, Image{File: f})
		} else if info.IsDir() {
			allFiles.Dirs = append(allFiles.Dirs, Dir{File: f, IsDir: true})
		} else {
			allFiles.Files = append(allFiles.Files, f)
		}
	}
	return allFiles, nil
}

func isImage(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, it := range imageTypes {
		if ext == it {
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

func isSubPath(child, parent string) bool {
	absChild, err := filepath.Abs(child)
	if err != nil {
		return false
	}
	absParent, err := filepath.Abs(parent)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absParent, absChild)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}
