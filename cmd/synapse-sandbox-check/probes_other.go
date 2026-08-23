//go:build !linux

package main

import (
	"fmt"
	"io"
)

func runProbe(args []string, out io.Writer) (bool, int) {
	return false, 0
}

func syscallPtrace() (uintptr, uintptr, error) {
	return 0, 0, fmt.Errorf("ptrace probe is Linux-only")
}
