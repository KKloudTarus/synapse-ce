//go:build !windows

package sensorstatejournal

import "os"

func replaceFile(from, to string) error {
	return os.Rename(from, to)
}
