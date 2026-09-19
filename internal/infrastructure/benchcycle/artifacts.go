package benchcycle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteNewFile creates parent directories and writes a new, durable file without overwrite.
func WriteNewFile(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return WriteFile(path, body, mode)
}

// WriteFile writes a new, durable file without replacing an existing file or symlink.
func WriteFile(path string, body []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// SyncDirectory durably persists prior directory changes where the platform supports it.
func SyncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if err := requireRealDirectory(path); err != nil {
		return fmt.Errorf("open bundle directory for sync: %w", err)
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open bundle directory for sync: %w", err)
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync bundle directory: %w", err)
	}
	return nil
}

func validatePublicationStage(stage string) error {
	if err := requireRealDirectory(stage); err != nil {
		return fmt.Errorf("validate output bundle staging directory: %w", err)
	}
	return nil
}

func requireRealDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a real directory")
	}
	return nil
}
