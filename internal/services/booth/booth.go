package booth

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"boxen_dispatch/internal/entities"
	"boxen_dispatch/internal/interfaces"
)

type Booth struct {
	Name string `json:"name" yaml:"name"`
	Path string `json:"path" yaml:"path"`
}

type Workspace struct {
	Booths []Booth `json:"booths" yaml:"booths"`
}

func (b *Workspace) Paths() (paths []string) {
	for _, booth := range b.Booths {
		paths = append(paths, booth.Path)
	}
	return
}

func Init() (interfaces.FS, error) {
	var booths []Booth
	boothFile := entities.Config.GetString("booth.file")
	storagePath := entities.Config.GetString("app.storage_path")
	data, err := os.ReadFile(filepath.Join(storagePath, boothFile))
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(data, &booths); err != nil {
		return nil, err
	}
	entities.Workspace = &Workspace{Booths: booths}
	return entities.Workspace, nil
}
