//go:build linux

package egressbroker

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func validateReplayOwner(info os.FileInfo, expectedUID int) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("owner identity is unavailable")
	}
	if int(stat.Uid) != expectedUID {
		return fmt.Errorf("owner UID is %d, want %d", stat.Uid, expectedUID)
	}
	return nil
}

func syncReplayDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}
