package local

import (
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"github.com/oarkflow/filebrowser/filesystem"
)

type Storage struct {
	basePath string
}

func NewStorage(base string) *Storage {
	abs, err := filepath.Abs(base)
	if err != nil {
		log.Fatalf("Error resolving base path %s: %v", base, err)
	}
	stat, err := os.Stat(abs)
	if err != nil || !stat.IsDir() {
		log.Fatalf("%s is not a valid directory", abs)
	}
	return &Storage{basePath: abs}
}

func (ls *Storage) resolvePath(path string) string {
	return filepath.Join(ls.basePath, path)
}

func (ls *Storage) BasePath() string {
	return ls.basePath
}

func (ls *Storage) ListDir(path string) ([]filesystem.FileInfo, error) {
	fullPath := ls.resolvePath(path)
	entries, err := os.ReadDir(fullPath)
	if err != nil {
		return nil, err
	}
	var infos []filesystem.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		infos = append(infos, filesystem.FileInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}
	return infos, nil
}

// ReadFile now returns the file content along with its MIME type.
func (ls *Storage) ReadFile(path string) ([]byte, string, error) {
	fullPath := ls.resolvePath(path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, "", err
	}
	// Attempt to determine MIME type using file extension.
	ext := filepath.Ext(fullPath)
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		// Fallback: detect MIME type from file content.
		mimeType = http.DetectContentType(data)
	}
	return data, mimeType, nil
}

func (ls *Storage) WriteFile(path string, content []byte) error {
	fullPath := ls.resolvePath(path)
	return os.WriteFile(fullPath, content, 0644)
}

func (ls *Storage) Remove(path string) error {
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

func (ls *Storage) Rename(oldPath, newPath string) error {
	return os.Rename(ls.resolvePath(oldPath), ls.resolvePath(newPath))
}

func (ls *Storage) CreateDir(path string) error {
	return os.Mkdir(ls.resolvePath(path), 0755)
}

func (ls *Storage) SaveUploadedFile(path string, file *multipart.FileHeader) error {
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
