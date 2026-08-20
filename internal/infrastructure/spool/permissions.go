package spool

import (
	"fmt"
	"os"
	"runtime"
)

// securePath tightens pre-existing spool paths as well as newly-created ones.
// Windows FileMode does not model ACLs, so Unix-bit verification is not claimed
// there; the package/service-owned state-directory ACL is authoritative.
func securePath(path string, mode os.FileMode) error {
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("%s mode is %o, want %o", path, info.Mode().Perm(), mode.Perm())
	}
	return nil
}
