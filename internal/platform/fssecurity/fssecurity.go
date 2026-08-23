// Package fssecurity exposes platform facts used when checking local secret-file protections.
package fssecurity

import "runtime"

// UnixModeEnforced reports whether Unix permission bits provide a real access-control guarantee.
// Windows os.Chmod only toggles a read-only attribute, so callers must rely on directory ACLs there.
func UnixModeEnforced() bool { return runtime.GOOS != "windows" }
