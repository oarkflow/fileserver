package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math"
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

var ACL = make(map[string]map[string][]string)

var users = map[string]*User{
	"admin":  {Username: "admin", PasswordHash: hashPassword("admin"), Role: "admin"},
	"editor": {Username: "editor", PasswordHash: hashPassword("editor"), Role: "editor"},
	"viewer": {Username: "viewer", PasswordHash: hashPassword("viewer"), Role: "viewer"},
}

type TemporaryLink struct {
	Token     string
	BaseIndex int
	FilePath  string
	Expiry    time.Time
}

var tempLinks = make(map[string]TemporaryLink)

var Storages []filesystem.Storage

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

func getAllFiles(fs filesystem.Storage, dir string) (AllFiles, error) {
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

func hashPassword(pwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

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

func checkPermission(user *User, path, action string) bool {
	if user.Role == "admin" {
		return true
	}

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

var store = fiberSession.New()

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

func requireAuth(c *fiber.Ctx) error {

	if c.Path() == "/login" || c.Path() == "/temp" || c.Path() == "/get" {
		return c.Next()
	}
	user := c.Locals("user")
	if user == nil {
		return c.Redirect("/login")
	}
	return c.Next()
}

func generateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
		for _, p := range args {

			storage := local.NewStorage(p)
			Storages = append(Storages, storage)
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

		app.Use(loadUser)
		app.Use(requireAuth)
		setupRoutes(app)
		url = fmt.Sprintf("%s:%s", ip, port)
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
	app.Get("/login", loginPage)
	app.Post("/login", loginPost)
	app.Get("/logout", logout)
	app.Get("/temp", tempLinkAccess)
	app.Get("/", dashboard)
	app.Get("/view", viewDir)
	app.Get("/get", getFile)
	app.Post("/upload", uploadFiles)
	app.Post("/delete", deleteFile)
	app.Post("/rename", renameItem)
	app.Post("/mkdir", makeDir)
	app.Get("/edit", editFile)
	app.Post("/save", saveFile)
	app.Post("/temp/generate", generateTemp)
	app.Get("/permissions", viewPermissions)
	app.Post("/permissions", updatePermissions)
	app.Get("/share", sharePage)
	app.Post("/share", sharePost)
}

func loginPage(c *fiber.Ctx) error {
	return c.Render("login", fiber.Map{
		"Title": "Login",
	})
}

func loginPost(c *fiber.Ctx) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	user, exists := users[username]
	if !exists {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password")
	}

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

func logout(c *fiber.Ctx) error {
	sess, err := store.Get(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("Session error")
	}

	sess.Destroy()
	return c.Redirect("/login")
}

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

func tempLinkAccess(c *fiber.Ctx) error {
	token := c.Query("token")
	link, exists := tempLinks[token]
	if !exists || time.Now().After(link.Expiry) {
		return c.Status(fiber.StatusNotFound).SendString("Temporary link expired or not found")
	}
	storage := Storages[link.BaseIndex]
	content, _, err := storage.ReadFile(link.FilePath)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}
	return c.Send(content)
}

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

func viewDir(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	dirParam := c.Query("dir", "")

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
	user, ok := c.Locals("user").(*User)
	baseIndex, err := strconv.Atoi(c.Query("base"))
	if err != nil || baseIndex < 0 || baseIndex >= len(Storages) {
		return c.Redirect("/")
	}
	fileParam := c.Query("file")
	if !ok {
		fmt.Println("User not found")
	}
	if user != nil && !checkPermission(user, fileParam, "view") {
		return c.Status(fiber.StatusForbidden).SendString("Permission denied")
	}
	storage := Storages[baseIndex]
	content, mimeType, err := storage.ReadFile(fileParam)
	if err != nil {
		return c.Status(fiber.StatusNotFound).SendString("File not found")
	}

	c.Set("Content-Type", mimeType)
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

func updatePermissions(c *fiber.Ctx) error {
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
	if ACL[path] == nil {
		ACL[path] = make(map[string][]string)
	}
	ACL[path][username] = actionList
	return c.Redirect("/permissions?path=" + path)
}

func sharePage(c *fiber.Ctx) error {
	user := c.Locals("user").(*User)

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
