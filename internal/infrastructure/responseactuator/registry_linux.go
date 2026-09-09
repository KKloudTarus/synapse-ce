//go:build linux

package responseactuator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

const (
	linuxUserTickNanos     = uint64(10_000_000)
	maxTrackedProcesses    = 4096
	maxRestartCmdlineBytes = 4096
)

type restartState uint8

const (
	restartNotAttempted restartState = iota
	restartStarted
	restartOutcomeUnknown
)

type trackedProcess struct {
	entityID      shared.ID
	pid           int
	pidfd         int
	startTick     uint64
	sequence      uint64
	launch        launchSpec
	executable    *pinnedDescriptor
	workingDir    *pinnedDescriptor
	stopRequested bool
	restart       restartState
	exited        bool
}

// launchSpec intentionally contains only the non-secret identity needed to start an eligible process.
// The command line and environment of the observed process are never retained.
type launchSpec struct {
	uid    uint32
	gid    uint32
	groups []uint32
}

type fileIdentity struct {
	dev  uint64
	ino  uint64
	mode uint32
	uid  uint32
	gid  uint32
}

type pinnedDescriptor struct {
	fd       int
	identity fileIdentity
}

// Registry pins process identities as pidfds when their durable eBPF observations pass through the
// agent. It deliberately does not discover arbitrary /proc entries: without the original boot/start
// observation, a bare PID cannot be bound to a ProcessEntityID safely.
type Registry struct {
	mu      sync.Mutex
	entries map[shared.ID]*trackedProcess
	order   uint64
}

func NewRegistry() (*Registry, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: live process response requires root so pidfd signals and identity reads fail closed", shared.ErrForbidden)
	}
	return &Registry{entries: make(map[shared.ID]*trackedProcess)}, nil
}

// ObserveProcess is called only after the canonical process observation is durable in the telemetry WAL.
func (r *Registry) ObserveProcess(assetID, bootID shared.ID, event detection.ProcessEvent) {
	if assetID.IsZero() || bootID.IsZero() || event.PID <= 1 || event.PID == os.Getpid() || event.StartTimeNanos == 0 {
		return
	}
	entityID := telemetry.ProcessEntityID(assetID, bootID, event.PID, event.StartTimeNanos)
	if event.Kind == "exit" {
		r.markExited(entityID)
		return
	}
	if event.Kind != "" && event.Kind != "exec" && event.Kind != "fork" {
		return
	}
	process, err := pinProcess(entityID, event.PID, event.StartTimeNanos, event.Kind == "exec")
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.order++
	process.sequence = r.order
	if prior := r.entries[entityID]; prior != nil {
		_ = prior.close()
	}
	r.entries[entityID] = process
	r.evictLocked()
}

func (r *Registry) StopProcess(ctx context.Context, entityID shared.ID) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	process := r.entries[entityID]
	if process == nil {
		return false, fmt.Errorf("%w: process target was not pinned from durable telemetry", shared.ErrNotFound)
	}
	// A prior SIGTERM is the only local post-condition this boundary can prove. Do not signal a
	// duplicate command again or claim that the process actually exited before telemetry confirms it.
	if process.stopRequested || process.exited {
		return true, nil
	}
	if err := revalidateProcess(process); err != nil {
		if process.exited {
			return true, nil
		}
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := unix.PidfdSendSignal(process.pidfd, unix.SIGTERM, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			process.exited = true
			return true, nil
		}
		return false, fmt.Errorf("send SIGTERM through pinned pidfd: %w", err)
	}
	process.stopRequested = true
	return false, nil
}

// RestartProcess launches an executable only after this registry sent SIGTERM to its exact prior process
// identity and the pidfd reports that identity has exited. A successful return means exec started; it does
// not assert a telemetry or application-health post-condition.
func (r *Registry) RestartProcess(ctx context.Context, entityID shared.ID) (alreadyRestarted bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	process := r.entries[entityID]
	if process == nil {
		return false, fmt.Errorf("%w: process target was not pinned from durable telemetry", shared.ErrNotFound)
	}
	switch process.restart {
	case restartStarted:
		return true, nil
	case restartOutcomeUnknown:
		return false, fmt.Errorf("%w: prior process restart launch has an unknown outcome", shared.ErrConflict)
	}
	if !process.stopRequested {
		return false, fmt.Errorf("%w: restart requires a prior local stop request", shared.ErrConflict)
	}
	exited, err := processExited(process)
	if err != nil {
		return false, err
	}
	if !exited {
		return false, fmt.Errorf("%w: original process is still live; refusing a duplicate restart", shared.ErrConflict)
	}
	if err := validateRestartableProcess(process); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	// os/exec maps ExtraFiles after its child-side chdir. The retained cwd remains available through the
	// inherited close-on-exec parent fd until exec, while ExtraFiles gives the executable a stable child fd 3.
	executable, err := childExecutablePath(process.executable)
	if err != nil {
		return false, err
	}
	workingDir, err := descriptorPath(process.workingDir)
	if err != nil {
		return false, err
	}
	// Do not use CommandContext here: the caller cancels its execution context after this method returns,
	// which would otherwise kill a successfully launched best-effort restart. Cancellation is checked before
	// launch and immediately after Start; a race after launch is reported as outcome-unknown below.
	cmd := exec.Command(executable)
	// Use only registry-generated argv[0] and an empty environment. The observed argv and environment can
	// contain credentials, so neither is stored, logged, inherited, or replayed.
	cmd.Args = []string{executable}
	cmd.Dir = workingDir
	cmd.Env = []string{}
	// The child needs executable fd 3 through exec path resolution. It is O_PATH-only and contains no data;
	// registry-owned descriptors remain close-on-exec and are closed by Registry.Close.
	// Duplicate the registry-owned descriptor for os/exec. os.StartProcess consumes its Files entries,
	// and handing it the registry's original fd would make future descriptor validation nondeterministically
	// observe EBADF after a successful child launch.
	executableFD, err := unix.Dup(process.executable.fd)
	if err != nil {
		return false, fmt.Errorf("duplicate pinned executable for restart: %w", err)
	}
	executableFile := os.NewFile(uintptr(executableFD), "pinned-executable")
	if executableFile == nil {
		_ = unix.Close(executableFD)
		return false, fmt.Errorf("%w: duplicate pinned executable is unavailable", shared.ErrForbidden)
	}
	defer func() { _ = executableFile.Close() }()
	cmd.ExtraFiles = []*os.File{executableFile}
	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: process.launch.uid, Gid: process.launch.gid, Groups: append([]uint32(nil), process.launch.groups...)},
		}
	} else if uint32(os.Geteuid()) != process.launch.uid || uint32(os.Getegid()) != process.launch.gid {
		return false, fmt.Errorf("%w: restart cannot preserve the observed process identity", shared.ErrForbidden)
	}
	if err := cmd.Start(); err != nil {
		return false, fmt.Errorf("start descriptor-pinned process: %w", err)
	}
	// Wait reaps the child and releases os/exec resources after the restarted process exits. It intentionally
	// does not manufacture a telemetry event or infer that the process remained healthy.
	go func() { _ = cmd.Wait() }()
	if err := ctx.Err(); err != nil {
		process.restart = restartOutcomeUnknown
		return false, err
	}
	process.restart = restartStarted
	return false, nil
}

func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var errs []error
	for id, process := range r.entries {
		if err := process.close(); err != nil {
			errs = append(errs, fmt.Errorf("close process descriptors %s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func (r *Registry) markExited(entityID shared.ID) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if process := r.entries[entityID]; process != nil {
		process.exited = true
	}
}

func (r *Registry) evictLocked() {
	for len(r.entries) > maxTrackedProcesses {
		var oldestID shared.ID
		oldestSequence := ^uint64(0)
		for id, process := range r.entries {
			if process.sequence < oldestSequence {
				oldestID, oldestSequence = id, process.sequence
			}
		}
		if process := r.entries[oldestID]; process != nil {
			_ = process.close()
		}
		delete(r.entries, oldestID)
	}
}

func pinProcess(entityID shared.ID, pid int, startTimeNanos uint64, captureRestart bool) (*trackedProcess, error) {
	startTick, err := readProcessStartTick(pid)
	if err != nil {
		return nil, err
	}
	if startTimeNanos/linuxUserTickNanos != startTick {
		return nil, fmt.Errorf("%w: live PID does not match the observed kernel start time", shared.ErrForbidden)
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("pin process pidfd: %w", err)
	}
	fail := func(err error) (*trackedProcess, error) {
		_ = unix.Close(pidfd)
		return nil, err
	}
	confirmedTick, err := readProcessStartTick(pid)
	if err != nil || confirmedTick != startTick {
		return fail(fmt.Errorf("%w: process identity changed while opening pidfd", shared.ErrConflict))
	}
	process := &trackedProcess{entityID: entityID, pid: pid, pidfd: pidfd, startTick: startTick}
	if !captureRestart {
		return process, nil
	}
	launch, executable, workingDir, err := captureRestartLaunch(pid)
	if err != nil {
		// Process stopping remains available for a durably observed process, but restart is deliberately
		// unavailable unless every capture check passed at the observation boundary.
		return process, nil
	}
	process.launch, process.executable, process.workingDir = launch, executable, workingDir
	return process, nil
}

func captureRestartLaunch(pid int) (launchSpec, *pinnedDescriptor, *pinnedDescriptor, error) {
	launch, err := readRestartIdentity(pid)
	if err != nil {
		return launchSpec{}, nil, nil, err
	}
	if err := requireNoProcessArgs(pid); err != nil {
		return launchSpec{}, nil, nil, err
	}
	executable, err := pinOwnedExecutable(pid, launch)
	if err != nil {
		return launchSpec{}, nil, nil, err
	}
	workingDir, err := pinOwnedWorkingDir(pid, launch)
	if err != nil {
		_ = executable.close()
		return launchSpec{}, nil, nil, err
	}
	return launch, executable, workingDir, nil
}

func pinOwnedExecutable(pid int, launch launchSpec) (*pinnedDescriptor, error) {
	// O_PATH retains the kernel-resolved executable identity without reopening a mutable filesystem pathname.
	fd, err := openObservedProcDescriptor(procFile(pid, "exe"), launch.uid, launch.gid, unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open observed process executable: %w", err)
	}
	descriptor, err := newPinnedDescriptor(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := validateExecutableDescriptor(descriptor, launch); err != nil {
		_ = descriptor.close()
		return nil, err
	}
	return descriptor, nil
}

func pinOwnedWorkingDir(pid int, launch launchSpec) (*pinnedDescriptor, error) {
	fd, err := openObservedProcDescriptor(procFile(pid, "cwd"), launch.uid, launch.gid, unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open observed process working directory: %w", err)
	}
	descriptor, err := newPinnedDescriptor(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := validateWorkingDirDescriptor(descriptor, launch); err != nil {
		_ = descriptor.close()
		return nil, err
	}
	return descriptor, nil
}

// openObservedProcDescriptor temporarily matches the target's filesystem identity on a pinned OS thread.
// Linux's procfs gate is credential based; merely holding uid 0 is insufficient in capability-constrained
// containers when the target is non-dumpable after a credential transition. No untrusted path is used: the
// only name is the kernel-owned /proc/<pid> entry bound to the pidfd/start-time validation above.
func openObservedProcDescriptor(path string, uid, gid uint32, flags int) (fd int, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	previousGID, err := unix.SetfsgidRetGid(int(gid))
	if err != nil {
		return -1, fmt.Errorf("match observed process filesystem group: %w", err)
	}
	previousUID, err := unix.SetfsuidRetUid(int(uid))
	if err != nil {
		_ = unix.Setfsgid(previousGID)
		return -1, fmt.Errorf("match observed process filesystem identity: %w", err)
	}
	defer func() {
		restoreErr := errors.Join(unix.Setfsuid(previousUID), unix.Setfsgid(previousGID))
		if restoreErr != nil && err == nil {
			err = fmt.Errorf("restore response filesystem identity: %w", restoreErr)
			if fd >= 0 {
				_ = unix.Close(fd)
				fd = -1
			}
		}
	}()
	fd, err = unix.Open(path, flags, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func revalidateProcess(process *trackedProcess) error {
	if process == nil || process.pidfd < 0 || process.pid <= 1 || process.pid == os.Getpid() {
		return fmt.Errorf("%w: process identity is not eligible for response", shared.ErrForbidden)
	}
	exited, err := processExited(process)
	if err != nil {
		return err
	}
	if exited {
		return fmt.Errorf("%w: pinned process has exited", shared.ErrConflict)
	}
	startTick, err := readProcessStartTick(process.pid)
	if err != nil || startTick != process.startTick {
		return fmt.Errorf("%w: live process no longer matches its pinned start time", shared.ErrConflict)
	}
	if process.executable != nil && !descriptorMatchesProc(process.executable, process.pid, "exe", process.launch.uid, process.launch.gid) {
		return fmt.Errorf("%w: live executable no longer matches its durable descriptor", shared.ErrConflict)
	}
	if process.workingDir != nil && !descriptorMatchesProc(process.workingDir, process.pid, "cwd", process.launch.uid, process.launch.gid) {
		return fmt.Errorf("%w: live working directory no longer matches its durable descriptor", shared.ErrConflict)
	}
	return nil
}

func processExited(process *trackedProcess) (bool, error) {
	if process == nil || process.pidfd < 0 {
		return false, fmt.Errorf("%w: process identity is not eligible for response", shared.ErrForbidden)
	}
	if process.exited {
		return true, nil
	}
	fds := []unix.PollFd{{Fd: int32(process.pidfd), Events: unix.POLLIN}}
	ready, err := unix.Poll(fds, 0)
	if err != nil {
		return false, fmt.Errorf("poll process pidfd: %w", err)
	}
	if ready != 0 {
		process.exited = true
		return true, nil
	}
	return false, nil
}

func validateRestartableProcess(process *trackedProcess) error {
	if process == nil || process.executable == nil || process.workingDir == nil {
		return fmt.Errorf("%w: observed process is not eligible for descriptor-pinned restart", shared.ErrForbidden)
	}
	if err := validateLaunchIdentity(process.launch); err != nil {
		return err
	}
	if err := validateExecutableDescriptor(process.executable, process.launch); err != nil {
		return err
	}
	return validateWorkingDirDescriptor(process.workingDir, process.launch)
}

func validateLaunchIdentity(launch launchSpec) error {
	if launch.uid == 0 || launch.gid == 0 {
		return fmt.Errorf("%w: root or root-group processes cannot be restarted", shared.ErrForbidden)
	}
	return nil
}

func validateExecutableDescriptor(descriptor *pinnedDescriptor, launch launchSpec) error {
	if err := validateLaunchIdentity(launch); err != nil {
		return err
	}
	identity, err := descriptor.currentIdentity()
	if err != nil {
		return err
	}
	if identity != descriptor.identity {
		return fmt.Errorf("%w: executable descriptor metadata changed after observation", shared.ErrConflict)
	}
	if identity.mode&unix.S_IFMT != unix.S_IFREG || identity.uid != launch.uid || identity.gid != launch.gid ||
		identity.mode&0077 != 0 || identity.mode&0100 == 0 || identity.mode&0400 == 0 || identity.mode&(unix.S_ISUID|unix.S_ISGID) != 0 {
		return fmt.Errorf("%w: executable is not a regular owner-only non-privileged file", shared.ErrForbidden)
	}
	return validateExecutableFormat(descriptor)
}

func validateExecutableFormat(descriptor *pinnedDescriptor) error {
	path, err := descriptorPath(descriptor)
	if err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open pinned executable for format validation: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	var magic [4]byte
	if _, err := unix.Pread(fd, magic[:], 0); err != nil {
		return fmt.Errorf("read pinned executable format: %w", err)
	}
	if !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) {
		return fmt.Errorf("%w: only direct ELF executable restarts are eligible", shared.ErrForbidden)
	}
	if err := rejectFileCapabilities(fd); err != nil {
		return err
	}
	return nil
}

func rejectFileCapabilities(fd int) error {
	data := make([]byte, 64)
	n, err := unix.Fgetxattr(fd, "security.capability", data)
	if err == nil {
		if n > 0 {
			return fmt.Errorf("%w: executable file capabilities are not eligible for restart", shared.ErrForbidden)
		}
		return nil
	}
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	return fmt.Errorf("read executable file capabilities: %w", err)
}

func validateWorkingDirDescriptor(descriptor *pinnedDescriptor, launch launchSpec) error {
	if err := validateLaunchIdentity(launch); err != nil {
		return err
	}
	identity, err := descriptor.currentIdentity()
	if err != nil {
		return err
	}
	if identity != descriptor.identity {
		return fmt.Errorf("%w: working-directory descriptor metadata changed after observation", shared.ErrConflict)
	}
	if identity.mode&unix.S_IFMT != unix.S_IFDIR || identity.uid != launch.uid || identity.gid != launch.gid ||
		identity.mode&0077 != 0 || identity.mode&0100 == 0 || identity.mode&unix.S_ISGID != 0 {
		return fmt.Errorf("%w: working directory is not an owner-only directory", shared.ErrForbidden)
	}
	return nil
}

func descriptorMatchesProc(descriptor *pinnedDescriptor, pid int, name string, uid, gid uint32) bool {
	if descriptor == nil || descriptor.fd < 0 {
		return false
	}
	fd, err := openObservedProcDescriptor(procFile(pid, name), uid, gid, unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	identity, err := fileIdentityForFD(fd)
	return err == nil && identity.dev == descriptor.identity.dev && identity.ino == descriptor.identity.ino
}

func childExecutablePath(executable *pinnedDescriptor) (string, error) {
	if executable == nil || executable.fd < 0 {
		return "", fmt.Errorf("%w: retained executable restart descriptor is unavailable", shared.ErrForbidden)
	}
	return "/proc/self/fd/3", nil
}

func descriptorPath(descriptor *pinnedDescriptor) (string, error) {
	if descriptor == nil || descriptor.fd < 0 {
		return "", fmt.Errorf("%w: retained restart descriptor is unavailable", shared.ErrForbidden)
	}
	return filepath.Join("/proc/self/fd", strconv.Itoa(descriptor.fd)), nil
}

func requireNoProcessArgs(pid int) error {
	fd, err := unix.Open(procFile(pid, "cmdline"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("read observed process command line: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	var data [maxRestartCmdlineBytes]byte
	used := 0
	for {
		if used == len(data) {
			return fmt.Errorf("%w: observed command line exceeds the restart safety limit", shared.ErrForbidden)
		}
		n, err := unix.Read(fd, data[used:])
		used += n
		if err == nil {
			if n == 0 {
				break
			}
			continue
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return fmt.Errorf("read observed process command line: %w", err)
	}
	firstNUL := bytes.IndexByte(data[:used], 0)
	if firstNUL <= 0 || firstNUL != used-1 {
		return fmt.Errorf("%w: process restart accepts only an observed executable with no arguments", shared.ErrForbidden)
	}
	return nil
}

func readRestartIdentity(pid int) (launchSpec, error) {
	data, err := os.ReadFile(procFile(pid, "status"))
	if err != nil {
		return launchSpec{}, fmt.Errorf("read process credentials: %w", err)
	}
	var uid, gid uint64
	var groups []uint32
	var foundUID, foundGID bool
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "Uid:":
			value, ok := uniformID(fields[1:])
			uid, foundUID = value, ok
		case "Gid:":
			value, ok := uniformID(fields[1:])
			gid, foundGID = value, ok
		case "Groups:":
			parsed, err := parseProcessGroups(fields[1:])
			if err != nil {
				return launchSpec{}, err
			}
			groups = parsed
		case "CapInh:", "CapPrm:", "CapEff:", "CapAmb:":
			value, parseErr := strconv.ParseUint(fields[1], 16, 64)
			if parseErr != nil || value != 0 {
				return launchSpec{}, fmt.Errorf("%w: process has unsafe credential state", shared.ErrForbidden)
			}
		}
	}
	if !foundUID || !foundGID {
		return launchSpec{}, fmt.Errorf("%w: process credentials are incomplete or changed", shared.ErrForbidden)
	}
	launch := launchSpec{uid: uint32(uid), gid: uint32(gid), groups: groups}
	if err := validateLaunchIdentity(launch); err != nil {
		return launchSpec{}, err
	}
	return launch, nil
}

func parseProcessGroups(fields []string) ([]uint32, error) {
	groups := make([]uint32, 0, len(fields))
	for _, field := range fields {
		group, err := strconv.ParseUint(field, 10, 32)
		if err != nil || group == 0 {
			return nil, fmt.Errorf("%w: process has an unsafe supplementary group", shared.ErrForbidden)
		}
		groups = append(groups, uint32(group))
	}
	return groups, nil
}

func uniformID(fields []string) (uint64, bool) {
	if len(fields) < 4 {
		return 0, false
	}
	var value uint64
	for i := 0; i < 4; i++ {
		parsed, err := strconv.ParseUint(fields[i], 10, 32)
		if err != nil || (i > 0 && parsed != value) {
			return 0, false
		}
		value = parsed
	}
	return value, true
}

func newPinnedDescriptor(fd int) (*pinnedDescriptor, error) {
	identity, err := fileIdentityForFD(fd)
	if err != nil {
		return nil, err
	}
	return &pinnedDescriptor{fd: fd, identity: identity}, nil
}

func (d *pinnedDescriptor) currentIdentity() (fileIdentity, error) {
	if d == nil || d.fd < 0 {
		return fileIdentity{}, fmt.Errorf("%w: retained descriptor is unavailable", shared.ErrForbidden)
	}
	return fileIdentityForFD(d.fd)
}

func fileIdentityForFD(fd int) (fileIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fileIdentity{}, fmt.Errorf("stat retained descriptor: %w", err)
	}
	return fileIdentity{dev: stat.Dev, ino: stat.Ino, mode: stat.Mode, uid: stat.Uid, gid: stat.Gid}, nil
}

func (d *pinnedDescriptor) close() error {
	if d == nil || d.fd < 0 {
		return nil
	}
	if err := unix.Close(d.fd); err != nil {
		return err
	}
	d.fd = -1
	return nil
}

func (p *trackedProcess) close() error {
	if p == nil {
		return nil
	}
	var errs []error
	if p.pidfd >= 0 {
		if err := unix.Close(p.pidfd); err != nil {
			errs = append(errs, err)
		}
		p.pidfd = -1
	}
	if err := p.executable.close(); err != nil {
		errs = append(errs, err)
	}
	if err := p.workingDir.close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func procFile(pid int, name string) string {
	return filepath.Join("/proc", strconv.Itoa(pid), name)
}

func readProcessStartTick(pid int) (uint64, error) {
	data, err := os.ReadFile(procFile(pid, "stat"))
	if err != nil {
		return 0, fmt.Errorf("read process stat: %w", err)
	}
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 {
		return 0, fmt.Errorf("%w: process stat has no command boundary", shared.ErrValidation)
	}
	fields := strings.Fields(string(data[closeParen+1:]))
	if len(fields) <= 19 {
		return 0, fmt.Errorf("%w: process stat is truncated", shared.ErrValidation)
	}
	startTick, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse process start tick: %w", err)
	}
	return startTick, nil
}
