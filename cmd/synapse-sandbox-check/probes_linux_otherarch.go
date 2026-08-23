//go:build linux && !amd64

package main

import "syscall"

func syscallPtrace() (uintptr, uintptr, syscall.Errno) {
	return 0, 0, syscall.ENOSYS
}
