//go:build linux && amd64

package ebpf

import _ "embed"

const embeddedObjectArch = "amd64"

//go:embed c/connlog.bpf.o
var connlogObj []byte

//go:embed c/exec.bpf.o
var execObj []byte

//go:embed c/file.bpf.o
var fileObj []byte

//go:embed c/priv.bpf.o
var privObj []byte

//go:embed c/netconn.bpf.o
var netObj []byte
