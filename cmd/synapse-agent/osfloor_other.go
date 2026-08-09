//go:build !windows

package main

// checkOSFloor is a no-op off Windows.
//
// The equivalent floor on Linux is the glibc version, and it is enforced where it can be enforced
// earliest: by the deb/rpm package dependency, which refuses to INSTALL below the floor rather than
// letting the binary fail at first start. See packaging/ and the libc-floor-refusal job in
// .github/workflows/agent-package-matrix.yml.
func checkOSFloor() error { return nil }
