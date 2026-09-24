//go:build linux

package scabench

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openPinnedBundleFile anchors each relative path component to an opened directory descriptor.
// O_NOFOLLOW rejects a substituted symlink and O_NONBLOCK keeps a FIFO substitution from blocking
// the caller before it can reject the non-regular descriptor.
func openPinnedBundleFile(root, relative string) (*os.File, error) {
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	fd := rootFD
	parts := strings.Split(relative, string(filepath.Separator))
	for index, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if index < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		if openErr != nil {
			_ = unix.Close(fd)
			return nil, openErr
		}
		_ = unix.Close(fd)
		fd = next
	}
	file := os.NewFile(uintptr(fd), relative)
	if file == nil {
		_ = unix.Close(fd)
		return nil, os.ErrInvalid
	}
	return file, nil
}
