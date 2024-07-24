package interfaces

type FS interface {
	Paths() (paths []string)
}
