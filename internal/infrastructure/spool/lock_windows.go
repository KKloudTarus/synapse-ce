//go:build windows

package spool

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func acquireDirectoryLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return f, nil
}

func releaseDirectoryLock(f *os.File) error {
	var overlapped windows.Overlapped
	unlockErr := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
	closeErr := f.Close()
	return errors.Join(unlockErr, closeErr)
}

func replaceFilePlatform(from, to string) error {
	fromPtr, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(fromPtr, toPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return nil
}

// Windows does not expose a portable directory-fsync primitive. MoveFileEx
// with WRITE_THROUGH above supplies the required rename durability.
func syncDirectory(string) error { return nil }
