//go:build linux && arm64

package ebpf

import _ "embed"

const embeddedObjectArch = "arm64"

//go:embed c/connlog.arm64.bpf.o
var connlogObj []byte

//go:embed c/exec.arm64.bpf.o
var execObj []byte

//go:embed c/file.arm64.bpf.o
var fileObj []byte

//go:embed c/priv.arm64.bpf.o
var privObj []byte

//go:embed c/netconn.arm64.bpf.o
var netObj []byte
