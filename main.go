package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oarkflow/browser"
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
	AUTH    bool
	CERT    string
	HOST    string
	KEY     string
	PASS    string
	PORT    string
	TLS     bool
	USER    string
	VERBOSE bool
	VERSION bool
	PATH    string
)

var imageTypes = []string{".png", ".jpg", "jpeg", ".gif"}

func init() {
	flag.StringVar(&HOST, "ip", "0.0.0.0", "IP address to serve on, defaults to 0.0.0.0")
	flag.StringVar(&HOST, "i", "0.0.0.0", "IP shortcut")
	flag.BoolVar(&VERSION, "version", false, "Print program version")
	flag.BoolVar(&VERSION, "V", false, "Version shortcut")
	flag.StringVar(&PORT, "port", "8080", "Port to listen on, defaults to 8080")
	flag.StringVar(&PORT, "p", "8080", "Port shortcut")
	flag.BoolVar(&TLS, "tls", false, "Generate and use self-signed TLS cert/key")
	flag.BoolVar(&TLS, "t", false, "TLS shortcut")
	flag.StringVar(&KEY, "key", "", "Use custom TLS Key, must also provide cert in PEM")
	flag.StringVar(&KEY, "k", "", "TLS key shortcut")
	flag.StringVar(&CERT, "cert", "", "Use custom TLS Cert, must also provide key")
	flag.StringVar(&CERT, "c", "", "TLS cert shortcut")
	flag.StringVar(&USER, "user", "", "Enable authentication with this username")
	flag.StringVar(&USER, "u", "", "Basic auth shortcut")
	flag.BoolVar(&VERBOSE, "verbose", false, "Enable verbose output")
	flag.BoolVar(&VERBOSE, "v", false, "Verbose shortcut")
}

func main() {
	var cert, key string
	flag.Usage = printHelp
	flag.Parse()
	if VERSION {
		log.Fatalln(Version)
	}
	if len(flag.Args()) == 0 {
		printUsage()
	}
	PATH = flag.Arg(0)
	if err := checkDir(PATH); err != nil {
		log.Fatalf("%v", err)
	}
	checkPem(CERT, KEY)
	if TLS {
		genKeys(HOST)
		cert = "cert.pem"
		key = "key.pem"
	}
	if len(CERT) > 0 && len(KEY) > 0 {
		cert = CERT
		key = KEY
	}
	if len(USER) > 0 {
		AUTH = true
		PASS = getPass()
	}
	setupRoutes()
	serving := HOST + ":" + PORT
	if len(CERT) > 0 || TLS {
		s := setupServerConfig(serving)
		url := fmt.Sprintf("https://%s", formatURL(true, HOST, PORT))
		if !isSudo() {
			_ = browser.OpenURL(url)
		}
		fmt.Println(`If using a self-signed certificate, ignore "unknown certificate" warnings`)
		fmt.Printf("\nServing on: %s\n", url)
		err := s.ListenAndServeTLS(cert, key)
		log.Fatal(err)
	} else {
		url := fmt.Sprintf("http://%s", formatURL(true, HOST, PORT))
		if !isSudo() {
			_ = browser.OpenURL(url)
		}
		fmt.Printf("\nServing on: %s\n", url)
		err := http.ListenAndServe(serving, nil)
		log.Fatal(err)
	}
}

func printUsage() {
	_, _ = fmt.Fprintf(os.Stderr, "usage: mini [-tv?V] [-c file] [-i host] [-k file] [-p port] [-u user] folder\n")
	_, _ = fmt.Fprintf(os.Stderr, `Try 'mini --help' or 'mini -h' for more information`+"\n")
	os.Exit(1)
}

func printHelp() {
	_, _ = fmt.Fprintf(os.Stderr, "Usage: mini [OPTION...] FOLDER\n")
	_, _ = fmt.Fprintf(os.Stderr, "Serve the given folder via an HTTP/S server\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -c, --cert=CERT           Use the provided PEM cert for TLS, MUST also use -k\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -i, --ip=HOST             IP address to serve on; default 0.0.0.0\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -k, --key=KEY             Use provided PEM key for TLS, MUST also use -c\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -p, --port=PORT           Port to serve on: default 8080\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -t, --tls                 Generate and use self-signed TLS cert.\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -u, --user=USERNAME       Enable basic auth. with this username\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -v, --verbose             Enable verbose logging mode\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -?, --help                Show this help message\n")
	_, _ = fmt.Fprintf(os.Stderr, "  -V, --version             Print program version\n")
	_, _ = fmt.Fprintf(os.Stderr, "\n")
}

func checkPem(cert, key string) {
	if (len(cert) > 0 && len(key) == 0) || (len(cert) == 0 && len(key) > 0) {
		log.Fatal("Error: must provide both a key and certificate in PEM format!")
	}
}

func setupRoutes() {
	http.HandleFunc("/", redirectRoot)
	http.HandleFunc("/get", getFile)
	http.HandleFunc("/upload", uploadFiles)
	http.HandleFunc("/view", viewDir)
	http.HandleFunc("/delete", deleteFile)
}

func setupServerConfig(host string) http.Server {
	return http.Server{
		Addr: host,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			},
		},
	}
}

func formatURL(tls bool, host, port string) string {
	if tls && port == "443" {
		return host
	} else if !tls && port == "80" {
		return host
	} else {
		return fmt.Sprintf("%s:%s", host, port)
	}
}

func createFile(name string) *os.File {
	f, err := os.Create(name)
	if err != nil {
		log.Fatalf("Failed to created file: %v", err)
	}
	return f
}

func closeFile(f *os.File) {
	err := f.Close()
	if err != nil {
		log.Fatalf("Error closing file: %v", err)
	}
}

func statFile(path string) fs.FileInfo {
	info, err := os.Stat(path)
	if err != nil {
		log.Fatalf("Error os.Stat() %s: %v", path, err)
	}
	return info
}

func checkDir(path string) error {
	info := statFile(path)
	if !info.IsDir() {
		return fmt.Errorf("error: not a directory %s", path)
	}
	return nil
}

func exists(path string) bool {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func maybeLog(msg string, addr string, path string) {
	if VERBOSE {
		log.Printf(msg, addr, path)
	}
}

func copyUploadFile(path string, src multipart.File) error {
	dst, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		_ = dst.Close()
	}()
	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}
	return err
}

func sizeToStr(n int64) string {
	if n == 0 {
		return "0B"
	}
	b := float64(n)
	units := []string{"B", "K", "M", "G", "T", "P", "E"}
	i := math.Floor(math.Log(b) / math.Log(1024))
	return strconv.FormatFloat((b/math.Pow(1024, i))*1, 'f', 1, 64) + units[int(i)]
}

func isImage(name string) bool {
	ext := filepath.Ext(name)
	mimeType := mime.TypeByExtension(ext)
	isImage := mimeType == "image/jpeg" || mimeType == "image/png" ||
		mimeType == "image/gif" || mimeType == "image/bmp" ||
		mimeType == "image/webp" || mimeType == "image/tiff" || mimeType == "image/svg+xml"

	return isImage
}

func fileFunc(path string) (AllFiles, error) {
	allFiles := AllFiles{}
	files, err := os.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		var f File
		var i Image
		var d Dir
		finfo, err := file.Info()
		if err != nil {
			continue
		}
		if finfo.IsDir() {
			d.Name = finfo.Name()
			d.Size = sizeToStr(finfo.Size())
			d.Mode = finfo.Mode().String()
			d.Date = finfo.ModTime().Format(time.DateTime)
			d.IsDir = true
			allFiles.Dirs = append(allFiles.Dirs, d)
		} else if isImage(finfo.Name()) {
			i.Name = finfo.Name()
			i.Size = sizeToStr(finfo.Size())
			i.Mode = finfo.Mode().String()
			i.Date = finfo.ModTime().Format(time.DateTime)
			allFiles.Images = append(allFiles.Images, i)
		} else {
			f.Name = finfo.Name()
			f.Size = sizeToStr(finfo.Size())
			f.Mode = finfo.Mode().String()
			f.Date = finfo.ModTime().Format(time.DateTime)
			allFiles.Files = append(allFiles.Files, f)
		}
	}
	return allFiles, nil
}

func checkAuth(_ http.ResponseWriter, r *http.Request) bool {
	if AUTH {
		user, pass, ok := r.BasicAuth()
		if !ok || (user != USER || !checkPass(pass, PASS)) {
			return false
		}
	}
	return true
}

func authFail(w http.ResponseWriter, r *http.Request) {
	maybeLog("CLIENT: %s PATH: %s: INCORRECT USERNAME/PASS\n", r.RemoteAddr, r.RequestURI)
	w.Header().Set("WWW-Authenticate", `Basic realm="api"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func redirectRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/view?dir=/", http.StatusFound)
}

func getFile(w http.ResponseWriter, r *http.Request) {
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}
	keys, ok := r.URL.Query()["file"]
	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		redirectRoot(w, r)
	}
	file := keys[0]
	if strings.Contains(file, "..") {

		redirectRoot(w, r)
		return
	}
	path := filepath.Clean(filepath.Join(PATH, file))
	if !exists(path) || strings.Contains(path, "..") {
		maybeLog("CLIENT: %s DOWNLOAD NOT FOUND: %s\n", r.RemoteAddr, path)
		http.Error(w, "File Not Found", http.StatusNotFound)
		return
	}
	filename := filepath.Base(path)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	maybeLog("CLIENT: %s DOWNLOAD: %s\n", r.RemoteAddr, path)
	http.ServeFile(w, r, path)
}

func uploadFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	if r.MultipartForm == nil {
		return
	}
	files := r.MultipartForm.File["file-upload"]
	dir := filepath.Clean(r.FormValue("directory"))
	if strings.Contains(dir, "..") {
		redirectRoot(w, r)
		return
	}
	for i := range files {
		path := filepath.Clean(filepath.Join(PATH, dir, files[i].Filename))
		file, err := files[i].Open()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		defer file.Close()
		if err = copyUploadFile(path, file); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		maybeLog("CLIENT: %s UPLOAD: %s\n", r.RemoteAddr, path)
	}
	http.Redirect(w, r, "view?dir="+dir, http.StatusFound)
}

func deleteFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}
	filename := r.FormValue("filename")
	if filename == "" {
		http.Error(w, "missing form value", http.StatusInternalServerError)
	}
	if strings.Contains(filename, "..") {
		redirectRoot(w, r)
		return
	}
	dir := r.FormValue("directory")
	path := filepath.Clean(filepath.Join(PATH, dir, filename))
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		maybeLog("CLIENT: %s DELETE NOT FOUND: %s\n", r.RemoteAddr, path)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	_ = os.Remove(path)
	maybeLog("CLIENT: %s DELETED: %s\n", r.RemoteAddr, path)
	http.Redirect(w, r, "view?dir="+dir, http.StatusFound)
}

func genKeys(host string) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(14 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Mini File Server"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}
	if exists("cert.pem") {
		log.Fatal("Failed to write cert.pem: file already exists!")
	}
	if err = writeCertFile("cert.pem", derBytes); err != nil {
		log.Fatalf("Failed to create TLS certificate")
	}
	if exists("key.pem") {
		log.Fatal("Failed to write key.pem: file already exists!")
	}
	if err = writeKeyFile("key.pem", priv); err != nil {
		log.Fatalf("Failed to write key file: %v", err)
	}
}

func writeKeyFile(name string, privKey *ecdsa.PrivateKey) error {
	keyOut := openKeyFile(name)
	defer closeFile(keyOut)
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	return err
}

func openKeyFile(name string) *os.File {
	keyOut, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to open key.pem for writing: %v", err)
	}
	return keyOut
}

func writeCertFile(name string, data []byte) error {
	certOut := createFile(name)
	defer closeFile(certOut)
	err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: data})
	return err
}

func getPass() string {
	reader := bufio.NewReader(os.Stdin)
	p1, p2 := "1", "2"
	for bad := true; bad; bad = p1 != p2 {
		fmt.Print("\nEnter password: ")
		p1, _ = reader.ReadString('\n')
		fmt.Print("Enter password again: ")
		p2, _ = reader.ReadString('\n')
	}
	hash := sha512.New()
	hash.Write([]byte(strings.TrimSpace(p1)))
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
}

func checkPass(input, password string) bool {
	sha := sha512.New()
	sha.Write([]byte(input))
	inpass := base64.StdEncoding.EncodeToString(sha.Sum(nil))
	return inpass == password
}

func isSudo() bool {
	return os.Geteuid() == 0
}

func viewDir(w http.ResponseWriter, r *http.Request) {
	bt, err := os.ReadFile("index.html")
	if err != nil {
		return
	}
	if !checkAuth(w, r) {
		authFail(w, r)
		return
	}
	maybeLog("CLIENT: %s PATH: %s\n", r.RemoteAddr, r.RequestURI)
	keys, ok := r.URL.Query()["dir"]
	if !ok || len(keys[0]) < 1 {
		log.Println("Url Param 'key' is missing")
		redirectRoot(w, r)
		return
	}
	dir := filepath.Clean(keys[0])
	dir = filepath.ToSlash(dir)
	parent := filepath.Dir(dir)
	if parent == "." {
		parent = "/"
	}
	if strings.Contains(dir, "..") {
		redirectRoot(w, r)
		return
	}
	path := filepath.Clean(filepath.Join(PATH, dir))
	if !exists(path) {
		maybeLog("CLIENT: %s BAD PATH: %s\n", r.RemoteAddr, path)
		http.Error(w, "File Not Found", http.StatusNotFound)
		return
	}
	f, err := fileFunc(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	title := "Directory listing for " + dir
	context := Context{Title: title, Directory: dir, Parent: parent, Files: f.Files, Dirs: f.Dirs, Images: f.Images}
	templates := template.Must(template.New("foo").Parse(string(bt)))
	if err := templates.Execute(w, context); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
