package local

import (
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"

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

func (ls *Storage) ReadFile(path string) ([]byte, string, error) {
	fullPath := ls.resolvePath(path)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, "", err
	}

	ext := filepath.Ext(fullPath)
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {

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

func DirSize(root string) (int64, error) {
	var totalSize int64
	var mu sync.Mutex
	visited := make(map[string]struct{})
	var dirWg sync.WaitGroup
	var workerWg sync.WaitGroup
	dirCh := make(chan string, 100)
	errCh := make(chan error, 1)
	worker := func() {
		defer workerWg.Done()
		for dir := range dirCh {
			entries, err := os.ReadDir(dir)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				dirWg.Done()
				continue
			}
			for _, entry := range entries {
				fullPath := filepath.Join(dir, entry.Name())
				var info os.FileInfo
				if entry.Type()&os.ModeSymlink != 0 {
					info, err = os.Stat(fullPath)
					if err != nil {
						select {
						case errCh <- err:
						default:
						}
						continue
					}
				} else {
					info, err = entry.Info()
					if err != nil {
						select {
						case errCh <- err:
						default:
						}
						continue
					}
				}
				if info.Mode().IsRegular() {
					mu.Lock()
					totalSize += info.Size()
					mu.Unlock()
				} else if info.IsDir() {
					absPath, err := filepath.Abs(fullPath)
					if err != nil {
						select {
						case errCh <- err:
						default:
						}
						continue
					}
					canonical, err := filepath.EvalSymlinks(absPath)
					if err != nil {
						select {
						case errCh <- err:
						default:
						}
						continue
					}
					mu.Lock()
					if _, ok := visited[canonical]; !ok {
						visited[canonical] = struct{}{}
						mu.Unlock()
						dirWg.Add(1)
						dirCh <- canonical
					} else {
						mu.Unlock()
					}
				}
			}
			dirWg.Done()
		}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return 0, err
	}
	canonicalRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return 0, err
	}
	visited[canonicalRoot] = struct{}{}
	dirWg.Add(1)
	dirCh <- canonicalRoot
	numWorkers := runtime.NumCPU()
	workerWg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}
	go func() {
		dirWg.Wait()
		close(dirCh)
	}()
	workerWg.Wait()
	select {
	case err, ok := <-errCh:
		if ok {
			return 0, err
		}
	default:
	}
	return totalSize, nil
}
