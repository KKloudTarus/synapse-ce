//go:build !linux

package egressbroker

import "os"

func validateReplayOwner(os.FileInfo, int) error {
	return nil
}

func syncReplayDirectory(string) error {
	return nil
}
