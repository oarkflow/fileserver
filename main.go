package main

import (
	"fmt"
	"log"
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

	"github.com/oarkflow/filebrowser/filesystem"
	"github.com/oarkflow/filebrowser/filesystem/local"
	"github.com/oarkflow/filebrowser/utils"
)

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

type User struct {
	Username     string
	PasswordHash string
	Role         string
}

func NewUser(username, password, role string) *User {
	return &User{
		Username:     username,
		PasswordHash: utils.HashPassword(password),
		Role:         role,
	}
}

type TemporaryLink struct {
	Token     string
	BaseIndex int
	FilePath  string
	Expiry    time.Time
}

type Manager struct {
	acl       map[string]map[string][]string
	users     map[string]*User
	tempLinks map[string]TemporaryLink
	storages  []filesystem.Storage
}

func (m *Manager) getAllFiles(fs filesystem.Storage, dir string) (AllFiles, error) {
	var allFiles AllFiles
	entries, err := fs.ListDir(dir)
	if err != nil {
		return allFiles, err
	}
	for _, entry := range entries {
		f := File{
			Name: entry.Name,
			Size: utils.HumanSize(entry.Size),
			Mode: fmt.Sprintf("%v", entry.Mode),
			Date: entry.ModTime.Format(time.RFC822),
		}
		if utils.IsImage(entry.Name) {
			allFiles.Images = append(allFiles.Images, Image{File: f})
		} else if entry.IsDir {
			allFiles.Dirs = append(allFiles.Dirs, Dir{File: f, IsDir: true})
		} else {
			allFiles.Files = append(allFiles.Files, f)
		}
	}
	return allFiles, nil
}

func (m *Manager) defaultPermission(role, action string) bool {
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

func (m *Manager) checkPermission(user *User, path, action string) bool {
	if user.Role == "admin" {
		return true
	}
	var matched string
	for aclPath := range m.acl {
		if strings.HasPrefix(path, aclPath) && len(aclPath) > len(matched) {
			matched = aclPath
		}
	}
	if matched != "" {
		allowedActions, ok := m.acl[matched][user.Username]
		if ok {
			for _, a := range allowedActions {
				if a == action {
					return true
				}
			}
			return false
		}
	}
	return m.defaultPermission(user.Role, action)
}

func (m *Manager) generateTemp(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndexStr := c.FormValue("base")
	baseIndex, err := strconv.Atoi(baseIndexStr)
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid storage base")
	}
	filePath := c.FormValue("file")
	expiryMinutesStr := c.FormValue("expiry")
	expiryMinutes, err := strconv.Atoi(expiryMinutesStr)
	if err != nil || expiryMinutes <= 0 {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid expiry time")
	}

	if !m.checkPermission(user, filePath, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	token, err := utils.GenerateToken(16)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Error generating token")
	}
	m.tempLinks[token] = TemporaryLink{
		Token:     token,
		BaseIndex: baseIndex,
		FilePath:  filePath,
		Expiry:    time.Now().Add(time.Duration(expiryMinutes) * time.Minute),
	}
	link := fmt.Sprintf("%s/temporary?token=%s", c.BaseURL(), token)
	return c.SendString(link)
}

func (m *Manager) tempLinkAccess(c *fiber.Ctx) error {
	token := c.Query("token")
	link, exists := m.tempLinks[token]
	if !exists || time.Now().After(link.Expiry) {
		return c.Status(fiber.StatusNotFound).SendString("Temporary link expired or not found")
	}
	storage := m.storages[link.BaseIndex]
	content, contentType, err := storage.ReadFile(link.FilePath)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	c.Set("Content-Type", contentType)
	return c.Send(content)
}

func (m *Manager) dashboard(c *fiber.Ctx) error {
	if len(m.storages) == 1 {
		return c.Redirect("/view?base=0")
	}
	var items []DashboardItem
	for i, storage := range m.storages {
		items = append(items, DashboardItem{Index: i, Path: storage.BasePath()})
	}
	ctx := DashboardContext{
		Title: "Shared storages",
		Bases: items,
	}
	return c.Render("dashboard", ctx)
}

func (m *Manager) viewDir(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	dirParam := c.Query("dir", "")
	if !m.checkPermission(user, dirParam, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := m.storages[baseIndex]
	allFiles, err := m.getAllFiles(storage, dirParam)
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

func (m *Manager) getFile(c *fiber.Ctx) error {
	user, _ := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	if user != nil && !m.checkPermission(user, fileParam, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := m.storages[baseIndex]
	content, mimeType, err := storage.ReadFile(fileParam)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	c.Set("Content-Type", mimeType)
	return c.Send(content)
}

func (m *Manager) uploadFiles(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	if !m.checkPermission(user, dirParam, "upload") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := m.storages[baseIndex]
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

func (m *Manager) deleteFile(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	pathParam := c.FormValue("path")
	if !m.checkPermission(user, pathParam, "delete") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := m.storages[baseIndex]
	if err := storage.Remove(pathParam); err != nil {
		return err
	}
	parent := filepath.Dir(pathParam)
	if parent == "." {
		parent = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, parent))
}

func (m *Manager) makeDir(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	dirParam := c.FormValue("directory", "")
	newDirName := c.FormValue("newDirName")
	if newDirName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Directory name required")
	}
	if !m.checkPermission(user, dirParam, "create") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := m.storages[baseIndex]
	targetDir := filepath.Join(dirParam, newDirName)
	if err := storage.CreateDir(targetDir); err != nil {
		return err
	}
	newRel := filepath.Join(dirParam, newDirName)
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, newRel))
}

func (m *Manager) renameItem(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	oldPath := c.FormValue("oldPath")
	newName := c.FormValue("newName")
	if newName == "" {
		return c.Status(fiber.StatusBadRequest).SendString("New name required")
	}
	if !m.checkPermission(user, oldPath, "edit") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := m.storages[baseIndex]
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

func (m *Manager) editFile(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	if !m.checkPermission(user, fileParam, "edit") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := m.storages[baseIndex]
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(fileParam)), ".")
	if !slices.Contains(utils.PlainText, ext) {
		return c.Status(fiber.StatusBadRequest).SendString("Editing not supported for this file type")
	}
	content, _, err := storage.ReadFile(fileParam)
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

func (m *Manager) saveFile(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.FormValue("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Redirect("/")
	}
	fileParam := c.FormValue("file")
	if !m.checkPermission(user, fileParam, "edit") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	content := c.FormValue("content")
	storage := m.storages[baseIndex]
	if err := storage.WriteFile(fileParam, []byte(content)); err != nil {
		return err
	}
	dirParam := filepath.Dir(fileParam)
	if dirParam == "." {
		dirParam = ""
	}
	return c.Redirect(fmt.Sprintf("/view?base=%d&dir=%s", baseIndex, dirParam))
}

func (m *Manager) viewPermissions(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	if user.Role != "admin" {
		return c.Status(fiber.StatusForbidden).SendString("Only admin can view permissions")
	}
	path := c.Query("path")
	var aclEntry map[string][]string
	if path != "" {
		aclEntry = m.acl[path]
	}
	return c.Render("permissions", fiber.Map{
		"Title":       "Permissions Management",
		"Path":        path,
		"Permissions": aclEntry,
	})
}

func (m *Manager) updatePermissions(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	if user.Role != "admin" {
		return c.Status(fiber.StatusForbidden).SendString("Only admin can update permissions")
	}
	path := c.FormValue("path")
	username := c.FormValue("username")
	actions := c.FormValue("actions")
	if path == "" || username == "" || actions == "" {
		return c.Status(fiber.StatusBadRequest).SendString("Missing parameters")
	}
	actionList := strings.Split(actions, ",")
	for i, a := range actionList {
		actionList[i] = strings.TrimSpace(a)
	}
	if m.acl[path] == nil {
		m.acl[path] = make(map[string][]string)
	}
	m.acl[path][username] = actionList
	return c.Redirect("/permissions?path=" + path)
}

func (m *Manager) sharePage(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	if user.Role != "admin" && user.Role != "editor" {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied for sharing")
	}
	fileParam := c.Query("file")
	if fileParam == "" {
		return c.Status(fiber.StatusBadRequest).SendString("File parameter required")
	}
	var links []TemporaryLink
	for _, tl := range m.tempLinks {
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

func (m *Manager) sharePost(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	if user.Role != "admin" && user.Role != "editor" {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied for sharing")
	}
	baseIndexStr := c.FormValue("base")
	baseIndex, err := strconv.Atoi(baseIndexStr)
	if err != nil || baseIndex < 0 || baseIndex >= len(m.storages) {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid storage base")
	}
	fileParam := c.FormValue("file")
	expiryMinutesStr := c.FormValue("expiry")
	expiryMinutes, err := strconv.Atoi(expiryMinutesStr)
	if err != nil || expiryMinutes <= 0 {
		return c.Status(fiber.StatusBadRequest).SendString("Invalid expiry time")
	}
	if !m.checkPermission(user, fileParam, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	token, err := utils.GenerateToken(16)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Error generating token")
	}
	m.tempLinks[token] = TemporaryLink{
		Token:     token,
		BaseIndex: baseIndex,
		FilePath:  fileParam,
		Expiry:    time.Now().Add(time.Duration(expiryMinutes) * time.Minute),
	}
	return c.Redirect(fmt.Sprintf("/share?file=%s", fileParam))
}

func (m *Manager) SetupRoutes(app *fiber.App, auth *AuthManager) {
	app.Get("/login", auth.loginPage)
	app.Post("/login", auth.loginPost)
	app.Get("/logout", auth.logout)

	app.Get("/temporary", m.tempLinkAccess)
	app.Get("/", m.dashboard)
	app.Get("/view", m.viewDir)
	app.Get("/get", m.getFile)
	app.Post("/upload", m.uploadFiles)
	app.Post("/delete", m.deleteFile)
	app.Post("/rename", m.renameItem)
	app.Post("/mkdir", m.makeDir)
	app.Get("/edit", m.editFile)
	app.Post("/save", m.saveFile)
	app.Post("/temporary", m.generateTemp)
	app.Get("/permissions", m.viewPermissions)
	app.Post("/permissions", m.updatePermissions)
	app.Get("/share", m.sharePage)
	app.Post("/share", m.sharePost)
}

type AuthManager struct {
	Store   *fiberSession.Store
	Manager *Manager
}

func (a *AuthManager) loadUser(c *fiber.Ctx) error {
	sess, err := a.Store.Get(c)
	if err != nil {
		return c.Status(500).SendString("Session error")
	}
	username := sess.Get("user")
	if usernameStr, ok := username.(string); ok {
		if u, exists := a.Manager.users[usernameStr]; exists {
			c.Locals("user", u)
		}
	}
	return c.Next()
}

func (a *AuthManager) requireAuth(c *fiber.Ctx) error {
	path := c.Path()
	embed := c.Query("embed", "false")
	if path == "/login" || (path == "/temporary" && c.Method() == "GET") || embed == "true" {
		return c.Next()
	}
	user := c.Locals("user")
	if user == nil {
		return c.Redirect("/login")
	}
	return c.Next()
}

func (a *AuthManager) loginPage(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login",
	})
}

func (a *AuthManager) loginPost(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	user, exists := a.Manager.users[username]
	if !exists {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
	}
	sess, err := a.Store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Session error")
	}
	sess.Set("user", user.Username)
	if err := sess.Save(); err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Failed to save session")
	}
	return c.Redirect("/")
}

func (a *AuthManager) logout(c *fiber.Ctx) error {
	sess, err := a.Store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Session error")
	}
	sess.Destroy()
	return c.Redirect("/login")
}

func main() {
	appCLI := cli.NewApp()
	appCLI.Name = "fs"
	appCLI.Usage = "Serve one or more storage backends via an HTTP file manager"
	appCLI.Version = "fs server 0.3.0 with auth, permissions & sharing"
	appCLI.Flags = []cli.Flag{
		&cli.StringFlag{Name: "ip", Aliases: []string{"i"}, Value: "0.0.0.0", Usage: "IP address to serve on"},
		&cli.StringFlag{Name: "port", Aliases: []string{"p"}, Value: "8080", Usage: "Port to listen on"},
		&cli.StringFlag{Name: "viewer-port", Aliases: []string{"vp"}, Value: "8081", Usage: "Port to listen viewer on"},
	}
	appCLI.Action = func(c *cli.Context) error {
		ip, port, viewerPort := c.String("ip"), c.String("port"), c.String("viewer-port")
		if c.NArg() == 0 {
			cli.ShowAppHelpAndExit(c, 1)
		}
		args := c.Args().Slice()
		manager := &Manager{
			acl:       make(map[string]map[string][]string),
			users:     make(map[string]*User),
			tempLinks: make(map[string]TemporaryLink),
			storages:  []filesystem.Storage{},
		}
		manager.users["admin"] = NewUser("admin", "admin", "admin")
		manager.users["editor"] = NewUser("editor", "editor", "editor")
		manager.users["viewer"] = NewUser("viewer", "viewer", "viewer")
		for _, p := range args {
			storage := local.NewStorage(p)
			manager.storages = append(manager.storages, storage)
		}
		engine := html.New("./views", ".html")
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
		static := fiber.New()
		static.Use(cors.New())
		static.Static("/", "./static/viewer-js")
		url := fmt.Sprintf("%s:%s", ip, viewerPort)
		go func() {
			_ = static.Listen(url)
		}()
		app.Use(cors.New())
		app.Static("/static", "./static", fiber.Static{
			Compress:  true,
			ByteRange: true,
		})
		app.Static("/webfonts", "./webfonts", fiber.Static{
			Compress:  true,
			ByteRange: true,
		})
		authManager := &AuthManager{
			Store:   fiberSession.New(),
			Manager: manager,
		}
		app.Use(authManager.loadUser)
		app.Use(authManager.requireAuth)
		manager.SetupRoutes(app, authManager)
		url = fmt.Sprintf("%s:%s", ip, port)
		log.Printf("\nServing on: http://%s\n", url)
		if !utils.IsSudo() {
			_ = browser.OpenURL("http://" + url)
		}
		log.Fatal(app.Listen(url))
		return nil
	}
	log.Fatal(appCLI.Run(os.Args))
}
