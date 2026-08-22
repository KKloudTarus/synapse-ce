//go:build linux && !amd64 && !arm64

package ebpf

// Keep the package cross-compilable on other Linux architectures while failing closed at runtime.
// No generic artifact is safe for target-specific kprobe register layouts.
const embeddedObjectArch = ""

var (
	connlogObj []byte
	execObj    []byte
	fileObj    []byte
	privObj    []byte
	netObj     []byte
)
