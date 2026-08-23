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
		fmt.Fprintln(out, "PASS")
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
		fmt.Fprintln(out, "PASS")
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
		fmt.Fprint(out, strings.Repeat("x", n))
		return true, 0
	case "redaction":
		fmt.Fprint(out, os.Getenv("SYNAPSE_PROBE_SECRET"))
		return true, 0
	default:
		fmt.Fprintln(out, "unknown probe")
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
		fmt.Fprintln(out, "FAIL")
		return 1
	}
	defer file.Close()
	for scanner := bufio.NewScanner(file); scanner.Scan(); {
		if strings.HasPrefix(scanner.Text(), "CapEff:") {
			if strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "CapEff:")) == "0000000000000000" {
				fmt.Fprintln(out, "PASS")
				return 0
			}
			break
		}
	}
	fmt.Fprintln(out, "FAIL")
	return 1
}

func probeNetwork(out io.Writer) int {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 750*time.Millisecond)
	if err == nil {
		conn.Close()
		fmt.Fprintln(out, "FAIL")
		return 1
	}
	fmt.Fprintln(out, "PASS")
	return 0
}

func probeFilesystem(out io.Writer, workdir, hidden string) int {
	if workdir == "" || hidden == "" {
		fmt.Fprintln(out, "FAIL")
		return 1
	}
	if err := os.WriteFile(filepath.Join(workdir, "sandbox-check-write"), []byte("ok"), 0o600); err != nil {
		fmt.Fprintln(out, "FAIL")
		return 1
	}
	if err := os.WriteFile("/etc/synapse-sandbox-check", []byte("must fail"), 0o600); err == nil {
		_ = os.Remove("/etc/synapse-sandbox-check")
		fmt.Fprintln(out, "FAIL")
		return 1
	}
	if _, err := os.Stat(filepath.Dir(hidden)); err == nil || !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(out, "FAIL")
		return 1
	}
	fmt.Fprintln(out, "PASS")
	return 0
}

func probeSeccomp(out io.Writer) int {
	// ptrace (x86_64 syscall 101) is intentionally absent from seccompAllow and must return EPERM.
	_, _, errno := syscallPtrace()
	if errno == 1 {
		fmt.Fprintln(out, "PASS")
		return 0
	}
	fmt.Fprintln(out, "FAIL")
	return 1
}

func probePids(out io.Writer) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(out, "FAIL")
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
			fmt.Fprintln(out, "PIDS_BLOCKED")
			return 0
		}
		children = append(children, child)
	}
	fmt.Fprintln(out, "FAIL")
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
	fmt.Fprintln(out, "FAIL")
	return 1
}
