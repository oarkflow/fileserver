package filesystem

import (
	"mime/multipart"
	"os"
	"time"
)

type FileInfo struct {
	Name    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
}

type Storage interface {
	// ListDir returns the list of files in the given (relative) directory.
	ListDir(path string) ([]FileInfo, error)
	// ReadFile returns the entire content of the file at the given (relative) path along with its MIME type.
	ReadFile(path string) ([]byte, string, error)
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
