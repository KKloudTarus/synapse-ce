//go:build windows

package main

import "golang.org/x/sys/windows"

// checkOSFloor refuses to run on a Windows build below the supported floor.
//
// RtlGetVersion is used rather than GetVersionEx precisely because it is NOT subject to the
// compatibility shim: GetVersionEx reports 6.3 build 9600 for any process without a matching
// compatibility manifest, which is how the MSI's own build condition ended up rejecting every
// supported host. This returns the real number.
func checkOSFloor() error {
	return windowsBuildSupported(windows.RtlGetVersion().BuildNumber)
}
