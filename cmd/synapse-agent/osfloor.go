package main

import "fmt"

// MinWindowsBuild is the oldest Windows build the agent supports: 17763 is Windows Server 2019 /
// Windows 10 1809, the floor stated in the support matrix (docs/guide/fleet-agent-packaging.md).
const MinWindowsBuild = 17763

// windowsBuildSupported reports whether a Windows build number is at or above the supported floor.
//
// This lives in the agent, not only in the MSI, because MSI cannot express it: msiexec reads the OS
// version through the compatibility shim and sees build 9600 on every release after Windows 8.1, so a
// package condition on the build number refuses supported hosts. The agent reads the true build
// through RtlGetVersion (osfloor_windows.go).
//
// Refusing to start is the point. An agent running on an unsupported host that reports host inventory
// anyway is worse than one that is absent: the fleet view shows a host as covered while the data behind
// it comes from a platform nobody tested, and that reads as coverage when it is not.
func windowsBuildSupported(build uint32) error {
	if build < MinWindowsBuild {
		return fmt.Errorf(
			"unsupported Windows build %d: the Synapse fleet agent requires build %d (Windows Server 2019 / Windows 10 1809) or later",
			build, MinWindowsBuild)
	}
	return nil
}
