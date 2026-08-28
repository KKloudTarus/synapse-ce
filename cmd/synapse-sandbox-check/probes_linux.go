//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func runProbe(args []string, out io.Writer) (bool, int) {
	probe, values := probeArguments(args)
	if probe == "" {
		return false, 0
	}
	switch probe {
	case "ok":
		_, _ = fmt.Fprintln(out, "PASS")
		return true, 0
	case "capabilities":
		return true, probeCapabilities(out)
	case "network":
		return true, probeNetwork(out)
	case "filesystem":
		return true, probeFilesystem(out, values["workdir"], values["hidden"])
	case "seccomp":
		return true, probeSeccomp(out)
	case "sleep":
		time.Sleep(30 * time.Second)
		_, _ = fmt.Fprintln(out, "PASS")
		return true, 0
	case "pids":
		return true, probePids(out)
	case "hold":
		time.Sleep(30 * time.Second)
		return true, 0
	case "memory":
		return true, probeMemory(out)
	case "output":
		n, _ := strconv.Atoi(values["bytes"])
		if n <= 0 {
			n = 8192
		}
		_, _ = fmt.Fprint(out, strings.Repeat("x", n))
		return true, 0
	case "redaction":
		_, _ = fmt.Fprint(out, os.Getenv("SYNAPSE_PROBE_SECRET"))
		return true, 0
	default:
		_, _ = fmt.Fprintln(out, "unknown probe")
		return true, 2
	}
}

func probeArguments(args []string) (string, map[string]string) {
	values := make(map[string]string)
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimPrefix(arg, "-"), "=")
		if ok {
			values[key] = value
		}
	}
	return values["probe"], values
}

func probeCapabilities(out io.Writer) int {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		_, _ = fmt.Fprintln(out, "FAIL")
		return 1
	}
	defer func() { _ = file.Close() }()
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		if strings.HasPrefix(scanner.Text(), "CapEff:") {
			if strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "CapEff:")) == "0000000000000000" {
				_, _ = fmt.Fprintln(out, "PASS")
				return 0
			}
			break
		}
	}
	_, _ = fmt.Fprintln(out, "FAIL")
	return 1
}

func probeNetwork(out io.Writer) int {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 750*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		_, _ = fmt.Fprintln(out, "FAIL")
		return 1
	}
	_, _ = fmt.Fprintln(out, "PASS")
	return 0
}

func probeFilesystem(out io.Writer, workdir, hidden string) int {
	if workdir == "" || hidden == "" {
		_, _ = fmt.Fprintln(out, "FAIL")
		return 1
	}
	if err := os.WriteFile(filepath.Join(workdir, "sandbox-check-write"), []byte("ok"), 0o600); err != nil {
		_, _ = fmt.Fprintln(out, "FAIL")
		return 1
	}
	if err := os.WriteFile("/etc/synapse-sandbox-check", []byte("must fail"), 0o600); err == nil {
		_ = os.Remove("/etc/synapse-sandbox-check")
		_, _ = fmt.Fprintln(out, "FAIL")
		return 1
	}
	if _, err := os.Stat(filepath.Dir(hidden)); err == nil || !errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(out, "FAIL")
		return 1
	}
	_, _ = fmt.Fprintln(out, "PASS")
	return 0
}

func probeSeccomp(out io.Writer) int {
	// ptrace (x86_64 syscall 101) is intentionally absent from seccompAllow and must return EPERM.
	_, _, errno := syscallPtrace()
	if errno == 1 {
		_, _ = fmt.Fprintln(out, "PASS")
		return 0
	}
	_, _ = fmt.Fprintln(out, "FAIL")
	return 1
}

func probePids(out io.Writer) int {
	self, err := os.Executable()
	if err != nil {
		_, _ = fmt.Fprintln(out, "FAIL")
		return 1
	}
	var children []*exec.Cmd
	defer func() {
		for _, child := range children {
			if child.Process != nil {
				_ = child.Process.Kill()
			}
		}
		for _, child := range children {
			_ = child.Wait()
		}
	}()
	for range 256 {
		child := exec.Command(self, "-probe=hold")
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintln(out, "PIDS_BLOCKED")
			return 0
		}
		children = append(children, child)
	}
	_, _ = fmt.Fprintln(out, "FAIL")
	return 1
}

func probeMemory(out io.Writer) int {
	var blocks [][]byte
	for range 128 {
		block := make([]byte, 8<<20)
		for i := range block {
			block[i] = 1
		}
		blocks = append(blocks, block)
	}
	runtime.KeepAlive(blocks)
	_, _ = fmt.Fprintln(out, "FAIL")
	return 1
}
