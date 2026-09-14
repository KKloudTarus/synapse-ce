//go:build windows

package reachcache

import "testing"

func makeFIFO(t *testing.T, _ string) {
	t.Helper()
	t.Skip("named pipes are not supported by this filesystem fixture on Windows")
}
