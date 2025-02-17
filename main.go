package main

import (
	"crypto/rand"
	"encoding/hex"
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
	fiberSession "github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
	"github.com/oarkflow/browser"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"
)

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
	User      string
}

type DashboardContext struct {
	Title string
	Bases []DashboardItem
}

type DashboardItem struct {
	Index int
	Path  string
}

// =============================================================================
// User and ACL Types
// =============================================================================

// User represents an authenticated user.
type User struct {
	Username     string
	PasswordHash string // stored as bcrypt hash
	Role         string // "admin", "editor", "viewer"
}

// ACL is a global per‑path access control list. For each path you can set
// which user (by username) is allowed which actions (e.g. "view", "edit", "delete", "upload", "create").
var ACL = make(map[string]map[string][]string)

// Global user map (for demo purposes only)
var users = map[string]*User{
	"admin":  {Username: "admin", PasswordHash: hashPassword("admin"), Role: "admin"},
	"editor": {Username: "editor", PasswordHash: hashPassword("editor"), Role: "editor"},
	"viewer": {Username: "viewer", PasswordHash: hashPassword("viewer"), Role: "viewer"},
}

// =============================================================================
// Temporary Link Types
// =============================================================================

// TemporaryLink represents a temporary URL for a file.
type TemporaryLink struct {
	Token     string
	BaseIndex int
	FilePath  string
	Expiry    time.Time
}

var tempLinks = make(map[string]TemporaryLink)

// =============================================================================
// FileStorage Interface and FileInfo (unchanged)
// =============================================================================

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

type FileInfo struct {
	Name    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
}

// =============================================================================
// LocalStorage Implementation (unchanged)
// =============================================================================

type LocalStorage struct {
	basePath string
}

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
// Global Storages Slice (unchanged)
// =============================================================================

var Storages []FileStorage

// =============================================================================
// Helper Functions for Templating and File Details (unchanged)
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
// Password Hashing Helpers
// =============================================================================

func hashPassword(pwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

// =============================================================================
// Permission Checking Helpers
// =============================================================================

// defaultPermission returns whether a role is allowed to perform a given action.
func defaultPermission(role, action string) bool {
	switch role {
	case "admin":
		return true
	case "editor":
		switch action {
		case "view", "upload", "create", "edit", "delete":
			return true
		}
	case "viewer":
		return action == "view"
	}
	return false
}

// checkPermission checks whether the given user is allowed to perform the action on the path.
func checkPermission(user *User, path, action string) bool {
	if user.Role == "admin" {
		return true
	}
	// Look for the longest ACL match.
	var matched string
	for aclPath := range ACL {
		if strings.HasPrefix(path, aclPath) && len(aclPath) > len(matched) {
			matched = aclPath
		}
	}
	if matched != "" {
		allowedActions, ok := ACL[matched][user.Username]
		if ok {
			for _, a := range allowedActions {
				if a == action {
					return true
				}
			}
			return false
		}
	}
	return defaultPermission(user.Role, action)
}

// =============================================================================
// Session and Authentication Middleware
// =============================================================================

var store = fiberSession.New()

// loadUser loads the user from the session (if present) and stores it in c.Locals.
func loadUser(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}
	username := sess.Get("user")
	if usernameStr, ok := username.(string); ok {
		if u, exists := users[usernameStr]; exists {
			c.Locals("user", u)
		}
	}
	return c.Next()
}

// requireAuth is a middleware that forces a logged-in user.
func requireAuth(c *fiber.Ctx) error {
	// Allow public endpoints.
	if c.Path() == "/login" || c.Path() == "/temp" {
		return c.Next()
	}
	user := c.Locals("user")
	if user == nil {
		return c.Redirect("/login")
	}
	return c.Next()
}

// =============================================================================
// Temporary Link Helpers
// =============================================================================

func generateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// =============================================================================
// Main and Route Handlers
// =============================================================================

func main() {
	appCLI := cli.NewApp()
	appCLI.Name = "fs"
	appCLI.Usage = "Serve one or more storage backends via an HTTP file manager"
	appCLI.Version = "fs server 0.3.0 with auth, permissions & sharing"
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
			// For now we assume a local storage.
			storage := NewLocalStorage(p)
			Storages = append(Storages, storage)
		}
		engine := html.New("./views", ".html")
		// Add helper functions to the template engine.
		engine.AddFuncMap(map[string]interface{}{
			"lower": strings.ToLower,
			"split": func(s, sep string) []string {
				parts := strings.Split(s, sep)
				if len(parts) == 1 {
					parts = append(parts, "na")
				}
				return parts
			},
			"join": strings.Join,
		})
		engine.Reload(true)
		app := fiber.New(fiber.Config{
			Views: engine,
		})
		app.Use(cors.New())
		// Load session user (if any) and enforce authentication.
		app.Use(loadUser)
		app.Use(requireAuth)
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
	// Public endpoints (login, temp link access)
	app.Get("/login", loginPage)
	app.Post("/login", loginPost)
	app.Get("/logout", logout)
	app.Get("/temp", tempLinkAccess)

	// Endpoints that require a user session:
	app.Get("/", dashboard)
	app.Get("/view", viewDir)
	app.Get("/get", getFile)
	app.Post("/upload", uploadFiles)
	app.Post("/delete", deleteFile)
	app.Post("/rename", renameItem)
	app.Post("/mkdir", makeDir)
	app.Get("/edit", editFile)
	app.Post("/save", saveFile)
	// Temporary link generation endpoint.
	app.Post("/temp/generate", generateTemp)

	// -------------------------------
	// New endpoints for ACL Management
	// -------------------------------
	app.Get("/permissions", viewPermissions)    // View current ACL for a given path (query parameter "path")
	app.Post("/permissions", updatePermissions) // Update ACL for a given path

	// -------------------------------
	// New endpoints for Sharing UI
	// -------------------------------
	app.Get("/share", sharePage)  // Display sharing options for a file (query parameter "file")
	app.Post("/share", sharePost) // Generate a new temporary share link
}

// -------------------------------
// Authentication Endpoints
// -------------------------------

// loginPage renders the login page.
func loginPage(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login",
	})
}

// loginPost processes the login form submission.
func loginPost(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	user, exists := users[username]
	if !exists {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
	}
	// Compare the provided password with the stored hash.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
	}

	// Save the user in session.
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Session error")
	}
	sess.Set("user", user.Username)
	if err := sess.Save(); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to save session")
	}
	return c.Redirect("/")
}

// logout destroys the user session and redirects to the login page.
func logout(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Session error")
	}
	// Destroy the session.
	sess.Destroy()
	return c.Redirect("/login")
}

// -------------------------------
// Temporary Link Endpoints
// -------------------------------

// generateTemp creates a temporary link for a file with a specified expiry (in minutes).
func generateTemp(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndexStr := c.FormValue("base")
	baseIndex, err := strconv.Atoi(baseIndexStr)
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid storage base")
	}
	filePath := c.FormValue("file")
	expiryMinutesStr := c.FormValue("expiry")
	expiryMinutes, err := strconv.Atoi(expiryMinutesStr)
	if err != nil || expiryMinutes <= 0 {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid expiry time")
	}
	// Check that the user has view permission for the file.
	if !checkPermission(user, filePath, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	token, err := generateToken(16)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Error generating token")
	}
	tempLinks[token] = TemporaryLink{
		Token:     token,
		BaseIndex: baseIndex,
		FilePath:  filePath,
		Expiry:    time.Now().Add(time.Duration(expiryMinutes) * time.Minute),
	}
	link := fmt.Sprintf("%s/temp?token=%s", c.BaseURL(), token)
	return c.SendString(link)
}

// tempLinkAccess serves a file via a temporary link.
func tempLinkAccess(c *fiber.Ctx) error {
	token := c.Query("token")
	link, exists := tempLinks[token]
	if !exists || time.Now().After(link.Expiry) {
		return c.Status(fiber.StatusNotFound).SendString("Temporary link expired or not found")
	}
	storage := Storages[link.BaseIndex]
	content, err := storage.ReadFile(link.FilePath)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	return c.Send(content)
}

// -------------------------------
// File Management Endpoints (view, upload, etc.)
// -------------------------------

func dashboard(c *fiber.Ctx) error {
	// If only one storage, redirect to its view.
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

func viewDir(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	dirParam := c.Query("dir", "")
	// Check permission on the directory (for "view")
	if !checkPermission(user, dirParam, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
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
		User:      user.Username,
	}
	return c.Render("index", ctx)
}

func getFile(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	if !checkPermission(user, fileParam, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := Storages[baseIndex]
	content, err := storage.ReadFile(fileParam)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	return c.Send(content)
}

func uploadFiles(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	if !checkPermission(user, dirParam, "upload") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
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

func deleteFile(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	pathParam := c.FormValue("path")
	if !checkPermission(user, pathParam, "delete") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
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

func makeDir(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	newDirName := c.FormValue("newDirName")
	if newDirName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Directory name required")
	}
	// Check permission on the parent directory for "create"
	if !checkPermission(user, dirParam, "create") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := Storages[baseIndex]
	targetDir := filepath.Join(dirParam, newDirName)
	if err := storage.CreateDir(targetDir); err != nil {
		return err
	}
	newRel := filepath.Join(dirParam, newDirName)
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, newRel))
}

func renameItem(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	oldPath := c.FormValue("oldPath")
	newName := c.FormValue("newName")
	if newName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("New name required")
	}
	if !checkPermission(user, oldPath, "edit") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
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

func editFile(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	if !checkPermission(user, fileParam, "edit") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
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

func saveFile(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	fileParam := c.FormValue("file")
	if !checkPermission(user, fileParam, "edit") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
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

var plainText = []string{
	"txt", "md", "csv", "log", "xml", "json", "yaml", "ini",
	"conf", "tsv", "properties", "rst", "dat", "tex", "cpp", "h",
	"cs", "js", "jsx", "ts", "tsx", "java", "py", "rb", "go",
	"swift", "php", "html", "css", "scss", "less", "bash", "sh",
	"zsh", "bat", "pl", "perl", "lua", "r", "sql", "json5", "yml",
	"c", "cpp", "dart", "m", "rs", "v", "clj", "el", "kt", "coffee",
	"vbs", "fs", "d", "as", "groovy", "hbs", "mustache",
}

// -------------------------------
// New Endpoints for ACL Management UI
// -------------------------------

// viewPermissions renders a page showing current ACL for a given path.
// Only admin can view and manage permissions.
func viewPermissions(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	if user.Role != "admin" {
		return c.Status(fiber.StatusForbidden).SendString("Only admin can view permissions")
	}
	path := c.Query("path")
	var aclEntry map[string][]string
	if path != "" {
		aclEntry = ACL[path]
	}
	return c.Render("permissions", fiber.Map{
		"Title":       "Permissions Management",
		"Path":        path,
		"Permissions": aclEntry,
	})
}

// updatePermissions updates the ACL for a given path.
func updatePermissions(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	if user.Role != "admin" {
		return c.Status(fiber.StatusForbidden).SendString("Only admin can update permissions")
	}
	path := c.FormValue("path")
	username := c.FormValue("username")
	actions := c.FormValue("actions") // comma-separated list
	if path == "" || username == "" || actions == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing parameters")
	}
	actionList := strings.Split(actions, ",")
	for i, a := range actionList {
		actionList[i] = strings.TrimSpace(a)
	}
	if ACL[path] == nil {
		ACL[path] = make(map[string][]string)
	}
	ACL[path][username] = actionList
	return c.Redirect("/permissions?path=" + path)
}

// -------------------------------
// New Endpoints for File and Folder Sharing UI
// -------------------------------

// sharePage displays a page with current share links for a file and a form to create new ones.
func sharePage(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	// For sharing, allow admin and editor roles.
	if user.Role != "admin" && user.Role != "editor" {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied for sharing")
	}
	fileParam := c.Query("file")
	if fileParam == "" {
		return c.Status(fiber.StatusBadRequest).SendString("File parameter required")
	}
	var links []TemporaryLink
	for _, tl := range tempLinks {
		if tl.FilePath == fileParam && time.Now().Before(tl.Expiry) {
			links = append(links, tl)
		}
	}
	return c.Render("share", fiber.Map{
		"Title":   "Sharing Options for " + fileParam,
		"File":    fileParam,
		"Links":   links,
		"BaseURL": c.BaseURL(),
	})
}

// sharePost processes the share form and generates a new temporary link.
func sharePost(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	if user.Role != "admin" && user.Role != "editor" {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied for sharing")
	}
	baseIndexStr := c.FormValue("base")
	baseIndex, err := strconv.Atoi(baseIndexStr)
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid storage base")
	}
	fileParam := c.FormValue("file")
	expiryMinutesStr := c.FormValue("expiry")
	expiryMinutes, err := strconv.Atoi(expiryMinutesStr)
	if err != nil || expiryMinutes <= 0 {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid expiry time")
	}
	// Check that the user has view permission for the file.
	if !checkPermission(user, fileParam, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	token, err := generateToken(16)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Error generating token")
	}
	tempLinks[token] = TemporaryLink{
		Token:     token,
		BaseIndex: baseIndex,
		FilePath:  fileParam,
		Expiry:    time.Now().Add(time.Duration(expiryMinutes) * time.Minute),
	}
	return c.Redirect(fmt.Sprintf("/share?file=%s", fileParam))
}
