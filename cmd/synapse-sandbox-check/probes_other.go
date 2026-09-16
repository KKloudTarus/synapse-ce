//go:build !linux

package main

import (
	"io"
)

func runProbe(args []string, out io.Writer) (bool, int) {
	return false, 0
}
