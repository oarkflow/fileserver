package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

func DirSize(root string) (int64, error) {
	var totalSize int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	fileCh := make(chan string, 100)
	errCh := make(chan error, 1)
	done := make(chan struct{})
	worker := func() {
		defer wg.Done()
		for filePath := range fileCh {
			info, err := os.Stat(filePath)
			if err != nil {
				errCh <- err
				return
			}
			if info.Mode().IsRegular() {
				mu.Lock()
				totalSize += info.Size()
				mu.Unlock()
			}
		}
	}
	numWorkers := runtime.NumCPU()
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go worker()
	}
	go func() {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				fileCh <- path
			}
			return nil
		})
		if err != nil {
			errCh <- err
		}
		close(fileCh)
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return totalSize, nil
	case err := <-errCh:
		return 0, err
	}
}

func main() {
	start := time.Now()
	dir := "/Users/sujit/Sites/clear"
	size, err := DirSize(dir)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Printf("Total size of directory %q is %d bytes %s\n", dir, size, time.Since(start))
}
