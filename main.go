package main

import (
	"fmt"
	"io"
	"log"
	"math"
	"mime/multipart"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/template/html/v2"
	"github.com/oarkflow/browser"
	"github.com/urfave/cli/v2"
)

var plainText = []string{
	"txt", "md", "csv", "log", "xml", "json", "yaml", "ini",
	"conf", "tsv", "properties", "rst", "dat", "tex", "cpp", "h",
	"cs", "js", "jsx", "ts", "tsx", "java", "py", "rb", "go",
	"swift", "php", "html", "css", "scss", "less", "bash", "sh",
	"zsh", "bat", "pl", "perl", "lua", "r", "sql", "json5", "yml",
	"c", "cpp", "dart", "m", "rs", "v", "clj", "el", "kt", "coffee",
	"vbs", "fs", "d", "as", "groovy", "hbs", "mustache",
}

// =============================================================================
// Shared Types used for Templating
// =============================================================================

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

const Version = "fs server 0.3.0" // updated version

// =============================================================================
// FileStorage Interface and FileInfo
// =============================================================================

// FileStorage defines the operations that any storage backend must implement.
type FileStorage interface {
	// ListDir returns the list of files in the given (relative) directory.
	ListDir(path string) ([]FileInfo, error)
	// ReadFile returns the entire content of the file at the given (relative) path.
	ReadFile(path string) ([]byte, error)
	// WriteFile writes the content to the file at the given (relative) path.
	WriteFile(path string, content []byte) error
	// Remove deletes the file or directory at the given (relative) path.
	Remove(path string) error
	// Rename renames a file or directory.
	Rename(oldPath, newPath string) error
	// CreateDir creates a directory at the given (relative) path.
	CreateDir(path string) error
	// SaveUploadedFile saves an uploaded file to the given (relative) path.
	SaveUploadedFile(path string, file *multipart.FileHeader) error
	// BasePath returns the storage’s base path or identifier.
	BasePath() string
}

// FileInfo is a simple wrapper for file metadata.
type FileInfo struct {
	Name    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
}

// =============================================================================
// LocalStorage Implementation
// =============================================================================

// LocalStorage implements FileStorage using the local OS filesystem.
type LocalStorage struct {
	basePath string
}

// NewLocalStorage creates a new LocalStorage instance.
// It resolves the absolute path and ensures the directory exists.
func NewLocalStorage(base string) *LocalStorage {
	abs, err := filepath.Abs(base)
	if err != nil {
		log.Fatalf("Error resolving base path %s: %v", base, err)
	}
	stat, err := os.Stat(abs)
	if err != nil || !stat.IsDir() {
		log.Fatalf("%s is not a valid directory", abs)
	}
	return &LocalStorage{basePath: abs}
}

// resolvePath combines the base path with the given relative path.
func (ls *LocalStorage) resolvePath(path string) string {
	return filepath.Join(ls.basePath, path)
}

func (ls *LocalStorage) BasePath() string {
	return ls.basePath
}

func (ls *LocalStorage) ListDir(path string) ([]FileInfo, error) {
	fullPath := ls.resolvePath(path)
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}
	var infos []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		infos = append(infos, FileInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}
	return infos, nil
}

func (ls *LocalStorage) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(ls.resolvePath(path))
}

func (ls *LocalStorage) WriteFile(path string, content []byte) error {
	fullPath := ls.resolvePath(path)
	return os.WriteFile(fullPath, content, 0644)
}

func (ls *LocalStorage) Remove(path string) error {
	fullPath := ls.resolvePath(path)
	fi, err := os.Stat(fullPath)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return os.RemoveAll(fullPath)
	}
	return os.Remove(fullPath)
}

func (ls *LocalStorage) Rename(oldPath, newPath string) error {
	return os.Rename(ls.resolvePath(oldPath), ls.resolvePath(newPath))
}

func (ls *LocalStorage) CreateDir(path string) error {
	return os.Mkdir(ls.resolvePath(path), 0755)
}

func (ls *LocalStorage) SaveUploadedFile(path string, file *multipart.FileHeader) error {
	src, err := file.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	fullPath := ls.resolvePath(path)
	// Ensure target directory exists.
	err = os.MkdirAll(filepath.Dir(fullPath), 0755)
	if err != nil {
		return err
	}
	dst, err := os.Create(fullPath)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// =============================================================================
// Global Storages Slice
// =============================================================================

// In this design, you can support multiple storage “bases” (e.g. local directories,
// S3 buckets, etc.) by adding their implementations to the Storages slice.
var Storages []FileStorage

// =============================================================================
// Helper Functions for Templating and File Details
// =============================================================================

var imageTypes = []string{".png", ".jpg", ".jpeg", ".gif", ".svg"}

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

// getAllFiles builds the AllFiles struct by reading the directory using the provided FileStorage.
func getAllFiles(fs FileStorage, dir string) (AllFiles, error) {
	var allFiles AllFiles
	entries, err := fs.ListDir(dir)
	if err != nil {
		return allFiles, err
	}
	for _, entry := range entries {
		f := File{
			Name: entry.Name,
			Size: humanSize(entry.Size),
			Mode: fmt.Sprintf("%v", entry.Mode),
			Date: entry.ModTime.Format(time.RFC822),
		}
		if isImage(entry.Name) {
			allFiles.Images = append(allFiles.Images, Image{File: f})
		} else if entry.IsDir {
			allFiles.Dirs = append(allFiles.Dirs, Dir{File: f, IsDir: true})
		} else {
			allFiles.Files = append(allFiles.Files, f)
		}
	}
	return allFiles, nil
}

// =============================================================================
// Main and Route Handlers
// =============================================================================

func main() {
	appCLI := cli.NewApp()
	appCLI.Name = "fs"
	appCLI.Usage = "Serve one or more storage backends via an HTTP file manager"
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
			// For now we assume a local storage. In the future, you can parse DSNs such as
			// "s3://bucket/..." or "minio://..." and create the proper storage.
			storage := NewLocalStorage(p)
			Storages = append(Storages, storage)
		}
		engine := html.New("./views", ".html")
		engine.AddFuncMap(map[string]any{
			"lower": strings.ToLower,
			"split": func(s string, sep string) []string {
				parts := strings.Split(s, sep)
				if len(parts) == 1 {
					parts = append(parts, "na")
				}
				return parts
			},
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

// dashboard shows a list of storage bases.
func dashboard(c *fiber.Ctx) error {
	if len(Storages) == 1 {
		return c.Redirect(fmt.Sprintf("/view?base=0"))
	}
	var items []DashboardItem
	for i, storage := range Storages {
		items = append(items, DashboardItem{Index: i, Path: storage.BasePath()})
	}
	ctx := DashboardContext{
		Title: "Shared Storages",
		Bases: items,
	}
	return c.Render("dashboard", ctx)
}

// viewDir lists the files of the requested directory.
func viewDir(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	dirParam := c.Query("dir", "")
	storage := Storages[baseIndex]
	allFiles, err := getAllFiles(storage, dirParam)
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
		Title:     "Directory listing for " + filepath.Join(storage.BasePath(), dirParam),
		BaseIndex: baseIndex,
		BasePath:  storage.BasePath(),
		Directory: dirParam,
		Parent:    parent,
		Files:     allFiles.Files,
		Dirs:      allFiles.Dirs,
		Images:    allFiles.Images,
	}
	return c.Render("index", ctx)
}

// getFile sends the content of the requested file.
func getFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	storage := Storages[baseIndex]
	content, err := storage.ReadFile(fileParam)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	return c.Send(content)
}

// uploadFiles saves uploaded files using the storage interface.
func uploadFiles(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	storage := Storages[baseIndex]
	form, err := c.MultipartForm()
	if err != nil {
		return err
	}
	for _, fileHeader := range form.File["file-upload"] {
		targetPath := filepath.Join(dirParam, fileHeader.Filename)
		if err := storage.SaveUploadedFile(targetPath, fileHeader); err != nil {
			return err
		}
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, dirParam))
}

// deleteFile removes a file or directory.
func deleteFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	pathParam := c.FormValue("path")
	storage := Storages[baseIndex]
	if err := storage.Remove(pathParam); err != nil {
		return err
	}
	parent := filepath.Dir(pathParam)
	if parent == "." {
		parent = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, parent))
}

// makeDir creates a new directory.
func makeDir(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	newDirName := c.FormValue("newDirName")
	if newDirName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Directory name required")
	}
	storage := Storages[baseIndex]
	targetDir := filepath.Join(dirParam, newDirName)
	if err := storage.CreateDir(targetDir); err != nil {
		return err
	}
	newRel := filepath.Join(dirParam, newDirName)
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, newRel))
}

// renameItem renames a file or directory.
func renameItem(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	oldPath := c.FormValue("oldPath")
	newName := c.FormValue("newName")
	if newName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("New name required")
	}
	storage := Storages[baseIndex]
	newPath := filepath.Join(filepath.Dir(oldPath), newName)
	if err := storage.Rename(oldPath, newPath); err != nil {
		return err
	}
	parent := filepath.Dir(oldPath)
	if parent == "." {
		parent = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, parent))
}

// editFile opens a text-based file for editing.
func editFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	storage := Storages[baseIndex]
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(fileParam)), ".")
	if !slices.Contains(plainText, ext) {
		return c.Status(fiber.StatusBadRequest).SendString("Editing not supported for this file type")
	}
	content, err := storage.ReadFile(fileParam)
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

// saveFile writes the edited content back to storage.
func saveFile(c *fiber.Ctx) error {
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	fileParam := c.FormValue("file")
	content := c.FormValue("content")
	storage := Storages[baseIndex]
	if err := storage.WriteFile(fileParam, []byte(content)); err != nil {
		return err
	}
	dirParam := filepath.Dir(fileParam)
	if dirParam == "." {
		dirParam = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, dirParam))
}

func isSudo() bool {
	return os.Geteuid() == 0
}
