//go:build !windows

package reachbench

func authorityPathIsReparsePoint(string) (bool, error) {
	return false, nil
}
