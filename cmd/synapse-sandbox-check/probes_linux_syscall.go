//go:build linux && amd64

package main

import "syscall"

func syscallPtrace() (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall(101, 0, 0, 0)
}
