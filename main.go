package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"math/big"
	"mime/multipart"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/browser"
	"github.com/urfave/cli/v2"
)

const Version = "mini server 0.1.7"

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
	CERT string
	HOST string
	KEY  string
	PORT string
	TLS  bool
	PATH string
)

var imageTypes = []string{".png", ".jpg", "jpeg", ".gif"}

func main() {
	app := cli.NewApp()
	app.Name = "mini"
	app.Usage = "Serve the given folder via an HTTP/S server"
	app.Version = Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{Name: "ip", Aliases: []string{"i"}, Value: "0.0.0.0", Usage: "IP address to serve on"},
		&cli.StringFlag{Name: "port", Aliases: []string{"p"}, Value: "8080", Usage: "Port to listen on"},
		&cli.BoolFlag{Name: "tls", Aliases: []string{"t"}, Usage: "Generate and use self-signed TLS cert/key"},
		&cli.StringFlag{Name: "key", Aliases: []string{"k"}, Usage: "Use custom TLS Key, must also provide cert in PEM"},
		&cli.StringFlag{Name: "cert", Aliases: []string{"c"}, Usage: "Use custom TLS Cert, must also provide key"},
	}

	app.Action = func(c *cli.Context) error {
		HOST = c.String("ip")
		PORT = c.String("port")
		TLS = c.Bool("tls")
		KEY = c.String("key")
		CERT = c.String("cert")

		if c.NArg() == 0 {
			cli.ShowAppHelpAndExit(c, 1)
		}

		PATH = c.Args().Get(0)
		if err := checkDir(PATH); err != nil {
			log.Fatalf("%v", err)
		}

		checkPem(CERT, KEY)

		var cert, key string
		if TLS {
			genKeys(HOST)
			cert = "cert.pem"
			key = "key.pem"
		}

		if len(CERT) > 0 && len(KEY) > 0 {
			cert = CERT
			key = KEY
		}

		app := fiber.New()
		setupRoutes(app)

		url := fmt.Sprintf("%s:%s", HOST, PORT)
		if len(cert) > 0 || TLS {
			log.Printf("\nServing on: https://%s\n", url)
			if !isSudo() {
				_ = browser.OpenURL("https://" + url)
			}
			err := app.ListenTLS(url, cert, key)
			log.Fatal(err)
		} else {
			log.Printf("\nServing on: http://%s\n", url)
			if !isSudo() {
				_ = browser.OpenURL("http://" + url)
			}
			err := app.Listen(url)
			log.Fatal(err)
		}
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
	return c.Redirect("/view?dir=/", fiber.StatusFound)
}

func getFile(c *fiber.Ctx) error {
	file := c.Query("file")
	if file == "" {
		return c.Redirect("/", fiber.StatusFound)
	}
	path := filepath.Clean(filepath.Join(PATH, file))
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
		path := filepath.Clean(filepath.Join(PATH, dir, file.Filename))
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
	path := filepath.Clean(filepath.Join(PATH, dir, filename))
	if !exists(path) {
		return c.Status(fiber.StatusInternalServerError).SendString("File not found")
	}
	_ = os.Remove(path)
	return c.Redirect("/view?dir="+dir, fiber.StatusFound)
}

func viewDir(c *fiber.Ctx) error {
	bt, err := os.ReadFile("index.html")
	if err != nil {
		return err
	}
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
	path := filepath.Clean(filepath.Join(PATH, dir))
	if !exists(path) {
		return c.Status(fiber.StatusNotFound).SendString("File Not Found")
	}
	f, err := fileFunc(path)
	if err != nil {
		return err
	}
	title := "Directory listing for " + dir
	context := Context{Title: title, Directory: dir, Parent: parent, Files: f.Files, Dirs: f.Dirs, Images: f.Images}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	templates := template.Must(template.New("foo").Parse(string(bt)))
	return templates.Execute(c.Response().BodyWriter(), context)
}

func checkPem(cert, key string) {
	if (len(cert) > 0 && len(key) == 0) || (len(cert) == 0 && len(key) > 0) {
		log.Fatal("Custom TLS cert/key requires both to be present")
	}
}

func genKeys(host string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	notBefore := time.Now()
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"mini"},
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	derBytes, _ := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	certOut, _ := os.Create("cert.pem")
	defer certOut.Close()
	_ = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyOut, _ := os.Create("key.pem")
	defer keyOut.Close()
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	_ = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
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
