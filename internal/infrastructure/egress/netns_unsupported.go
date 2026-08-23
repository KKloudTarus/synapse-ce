//go:build !linux

package egress

import (
	"errors"
	"os"
)

func pinNetworkNamespace(string, int) (string, error) {
	return "", errors.New("network namespace pinning is Linux-only")
}

func pinNetworkNamespaceAt(string, string, int) (string, error) {
	return "", errors.New("network namespace pinning is Linux-only")
}

func removePinnedNetworkNamespace(target string) error {
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
