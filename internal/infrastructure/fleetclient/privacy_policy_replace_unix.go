//go:build !windows

package fleetclient

import "os"

func replacePrivacyPolicyFile(from, to string) error {
	return os.Rename(from, to)
}
