//go:build linux

package egressbroker

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type peerIdentity struct {
	pid int
	uid int
	gid int
}

type sandboxProcess struct {
	pidfd   int
	netnsFD int
}

func peerIdentityFromConn(conn net.Conn) (peerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return peerIdentity{}, errors.New("egress broker accepts only Unix socket connections")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return peerIdentity{}, fmt.Errorf("get Unix connection descriptor: %w", err)
	}
	var cred *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return peerIdentity{}, fmt.Errorf("read Unix peer credentials: %w", err)
	}
	if sockErr != nil {
		return peerIdentity{}, fmt.Errorf("read Unix peer credentials: %w", sockErr)
	}
	if cred == nil || cred.Pid <= 1 {
		return peerIdentity{}, errors.New("Unix peer credentials contain an invalid pid")
	}
	return peerIdentity{pid: int(cred.Pid), uid: int(cred.Uid), gid: int(cred.Gid)}, nil
}

func authorizeSandboxProcess(peer peerIdentity, pid int, workerUID int, bwrapPath string) (*sandboxProcess, error) {
	if peer.uid != workerUID {
		return nil, fmt.Errorf("peer uid %d is not the configured worker uid", peer.uid)
	}
	if pid <= 1 || pid == peer.pid {
		return nil, errors.New("sandbox pid must identify a child process")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("open sandbox pidfd: %w", err)
	}
	process := &sandboxProcess{pidfd: pidfd, netnsFD: -1}
	fail := func(err error) (*sandboxProcess, error) {
		_ = process.Close()
		return nil, err
	}
	if err := process.Alive(); err != nil {
		return fail(fmt.Errorf("sandbox process is not alive: %w", err))
	}
	if err := requireDescendant(pid, peer.pid, workerUID); err != nil {
		return fail(err)
	}
	if err := requireBubblewrapProcess(pid, bwrapPath); err != nil {
		return fail(err)
	}
	if err := requirePrivateNamespaces(pid, peer.pid); err != nil {
		return fail(err)
	}
	netnsFD, err := unix.Open(filepath.Join("/proc", strconv.Itoa(pid), "ns", "net"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(fmt.Errorf("pin sandbox network namespace: %w", err))
	}
	process.netnsFD = netnsFD
	if err := process.Alive(); err != nil {
		return fail(fmt.Errorf("sandbox process exited while pinning network namespace: %w", err))
	}
	return process, nil
}

func (p *sandboxProcess) Alive() error {
	if p == nil || p.pidfd < 0 {
		return errors.New("sandbox process identity is closed")
	}

	fds := []unix.PollFd{{Fd: int32(p.pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return fmt.Errorf("poll sandbox pidfd: %w", err)
	}
	if n == 0 {
		return nil
	}

	revents := fds[0].Revents
	if revents&unix.POLLNVAL != 0 {
		return errors.New("sandbox process pidfd is invalid")
	}
	if revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR) != 0 {
		return fmt.Errorf("sandbox process exited (pidfd events %#x)", revents)
	}
	return fmt.Errorf("poll sandbox pidfd returned unexpected events %#x", revents)
}

func (p *sandboxProcess) NetworkNamespaceFD() int {
	if p == nil {
		return -1
	}
	return p.netnsFD
}

func (p *sandboxProcess) Close() error {
	if p == nil {
		return nil
	}
	var firstErr error
	if p.netnsFD >= 0 {
		if err := unix.Close(p.netnsFD); err != nil {
			firstErr = err
		}
		p.netnsFD = -1
	}
	if p.pidfd >= 0 {
		if err := unix.Close(p.pidfd); err != nil && firstErr == nil {
			firstErr = err
		}
		p.pidfd = -1
	}
	return firstErr
}

func requireDescendant(pid, ancestor, workerUID int) error {
	current := pid
	for range 64 {
		status, err := readProcStatus(current)
		if err != nil {
			return fmt.Errorf("inspect process ancestry: %w", err)
		}
		if status.uid != workerUID {
			return fmt.Errorf("process %d uid %d does not match worker uid %d", current, status.uid, workerUID)
		}
		if status.parent == ancestor {
			return nil
		}
		if status.parent <= 1 || status.parent == current {
			break
		}
		current = status.parent
	}
	return fmt.Errorf("sandbox pid %d is not a descendant of peer pid %d", pid, ancestor)
}

type procStatus struct {
	parent int
	uid    int
}

func readProcStatus(pid int) (procStatus, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return procStatus{}, err
	}
	var (
		out         procStatus
		foundParent bool
		foundUID    bool
	)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "PPid:":
			out.parent, err = strconv.Atoi(fields[1])
			foundParent = err == nil
		case "Uid:":
			out.uid, err = strconv.Atoi(fields[1])
			foundUID = err == nil
		}
		if err != nil {
			return procStatus{}, err
		}
	}
	if !foundParent || !foundUID {
		return procStatus{}, errors.New("process status is incomplete")
	}
	return out, nil
}

func requireBubblewrapProcess(pid int, expectedPath string) error {
	expected, err := os.Stat(expectedPath)
	if err != nil {
		return fmt.Errorf("stat configured bubblewrap: %w", err)
	}
	actual, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return fmt.Errorf("stat sandbox executable: %w", err)
	}
	if !os.SameFile(expected, actual) {
		return errors.New("sandbox process is not the configured bubblewrap executable")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return fmt.Errorf("read bubblewrap command line: %w", err)
	}
	args := splitCmdline(data)
	for _, flag := range []string{"--unshare-all", "--die-with-parent", "--new-session", "--seccomp", "--block-fd", "--json-status-fd", "--"} {
		if !containsArg(args, flag) {
			return fmt.Errorf("bubblewrap command is missing required %s flag", flag)
		}
	}
	if containsArg(args, "--share-net") {
		return errors.New("bubblewrap command unexpectedly shares the host network")
	}
	blockFD, err := flagFD(args, "--block-fd")
	if err != nil {
		return err
	}
	statusFD, err := flagFD(args, "--json-status-fd")
	if err != nil {
		return err
	}
	if blockFD == statusFD {
		return errors.New("bubblewrap block and status descriptors must be distinct")
	}
	return requireBubblewrapPipes(pid, blockFD, statusFD)
}

// requireBubblewrapPipes proves that the reported child is still paused on the inherited
// synchronization pipe. Bubblewrap closes --json-status-fd immediately after publishing
// child-pid, so that descriptor may legitimately be absent by the time the broker receives
// the request. If it remains open, it must still identify a pipe; all other inspection errors
// fail closed.
func requireBubblewrapPipes(pid, blockFD, statusFD int) error {
	blockTarget, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(blockFD)))
	if err != nil {
		return fmt.Errorf("inspect bubblewrap block fd %d: %w", blockFD, err)
	}
	if !strings.HasPrefix(blockTarget, "pipe:[") {
		return fmt.Errorf("bubblewrap block fd %d is not a pipe", blockFD)
	}

	statusTarget, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", strconv.Itoa(statusFD)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect bubblewrap status fd %d: %w", statusFD, err)
	}
	if !strings.HasPrefix(statusTarget, "pipe:[") {
		return fmt.Errorf("bubblewrap status fd %d is not a pipe", statusFD)
	}
	return nil
}

func splitCmdline(data []byte) []string {
	parts := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, string(part))
	}
	return out
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func flagFD(args []string, flag string) (int, error) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] != flag {
			continue
		}
		fd, err := strconv.Atoi(args[i+1])
		if err != nil || fd < 3 {
			return 0, fmt.Errorf("bubblewrap %s value is not a valid inherited fd", flag)
		}
		return fd, nil
	}
	return 0, fmt.Errorf("bubblewrap command is missing a value for %s", flag)
}

func requirePrivateNamespaces(pid, peerPID int) error {
	for _, namespace := range []string{"net", "user", "pid", "mnt"} {
		target, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid), "ns", namespace))
		if err != nil {
			return fmt.Errorf("stat sandbox %s namespace: %w", namespace, err)
		}
		peer, err := os.Stat(filepath.Join("/proc", strconv.Itoa(peerPID), "ns", namespace))
		if err != nil {
			return fmt.Errorf("stat peer %s namespace: %w", namespace, err)
		}
		if os.SameFile(target, peer) {
			return fmt.Errorf("sandbox process shares the peer %s namespace", namespace)
		}
	}
	return nil
}
