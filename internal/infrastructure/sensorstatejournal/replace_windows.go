//go:build windows

package sensorstatejournal

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func replaceFile(from, to string) error {
	fromPtr, err := syscall.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	toPtr, err := syscall.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		fromPtr,
		toPtr,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
