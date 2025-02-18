package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var ImageTypes = []string{
	".png", ".jpg", ".jpeg", ".gif", ".svg",
}

var PlainText = []string{
	"txt", "md", "csv", "log", "xml", "json", "yaml", "ini",
	"conf", "tsv", "properties", "rst", "dat", "tex", "cpp", "h",
	"cs", "js", "jsx", "ts", "tsx", "java", "py", "rb", "go",
	"swift", "php", "html", "css", "scss", "less", "bash", "sh",
	"zsh", "bat", "pl", "perl", "lua", "r", "sql", "json5", "yml",
	"c", "cpp", "dart", "m", "rs", "v", "clj", "el", "kt", "coffee",
	"vbs", "fs", "d", "as", "groovy", "hbs", "mustache",
}

func GenerateToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func IsSudo() bool {
	return os.Geteuid() == 0
}

func HumanSize(size int64) string {
	if size == 0 {
		return "0"
	}
	sizes := []string{"B", "K", "M", "G"}
	i := int(math.Floor(math.Log(float64(size)) / math.Log(1024)))
	return fmt.Sprintf("%.1f %s", float64(size)/math.Pow(1024, float64(i)), sizes[i])
}

func HashPassword(pwd string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	return string(hash)
}

func IsImage(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	for _, it := range ImageTypes {
		if ext == it {
			return true
		}
	}
	return false
}
