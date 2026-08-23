//go:build linux

package egress

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

func pinNetworkNamespace(name string, namespaceFD int) (string, error) {
	return pinNetworkNamespaceAt(networkNamespaceDir, name, namespaceFD)
}

func pinNetworkNamespaceAt(dir, name string, namespaceFD int) (string, error) {
	if namespaceFD < 0 {
		return "", errors.New("invalid network namespace descriptor")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create network namespace directory: %w", err)
	}
	target := filepath.Join(dir, name)
	fd, err := unix.Open(target, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", fmt.Errorf("create namespace mountpoint: %w", err)
	}
	if err := unix.Close(fd); err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("close namespace mountpoint: %w", err)
	}
	source := filepath.Join("/proc", "self", "fd", strconv.Itoa(namespaceFD))
	if err := unix.Mount(source, target, "none", unix.MS_BIND, ""); err != nil {
		_ = os.Remove(target)
		return "", fmt.Errorf("bind network namespace descriptor: %w", err)
	}
	return target, nil
}

func removePinnedNetworkNamespace(target string) error {
	if target == "" {
		return nil
	}
	var firstErr error
	if err := unix.Unmount(target, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
		firstErr = err
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
