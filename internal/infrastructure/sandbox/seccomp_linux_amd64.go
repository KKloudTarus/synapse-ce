//go:build linux && amd64

// seccomp_linux_amd64.go builds the seccomp-BPF syscall filter handed to bubblewrap via
// `--seccomp <fd>` (F1). The filter is DEFAULT-DENY: it returns EPERM for any syscall not
// on the explicit allowlist, and KILLs the process on a foreign architecture. The
// allowlist is the set a Go/C tool (syft, grype, naabu, subfinder, httpx, crane, git)
// needs to run – it deliberately OMITS the dangerous syscalls a malicious tool/input would
// reach for: ptrace, process_vm_*, bpf, keyctl, add_key, request_key, userfaultfd, unshare,
// setns, mount, umount2, pivot_root, kexec_*, *_module, perf_event_open, io_uring_*,
// reboot, swapon/off, modify_ldt, iopl/ioperm, clock_settime, settimeofday, sethostname.
//
// AF_PACKET raw sockets are blocked structurally (CAP_NET_RAW is no longer granted – F6),
// so this filter need not arg-inspect socket(2); socket() stays allowed for normal
// TCP/UDP. The program is emitted as raw `struct sock_filter` bytes (native-endian), the
// format bwrap's --seccomp fd expects (cf. seccomp_export_bpf).
package sandbox

import (
	"bytes"
	"encoding/binary"
	"os"

	"golang.org/x/sys/unix"
)

// seccomp BPF return actions + classic-BPF opcodes (no extra dep; we control jump offsets).
const (
	seccompRetAllow       = 0x7FFF0000
	seccompRetErrnoEPERM  = 0x00050000 | 1  // SECCOMP_RET_ERRNO | EPERM
	seccompRetErrnoENOSYS = 0x00050000 | 38 // SECCOMP_RET_ERRNO | ENOSYS (forces glibc clone3→clone fallback)
	seccompRetKillProcess = 0x80000000

	auditArchX8664 = 0xC000003E // AUDIT_ARCH_X86_64

	bpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfAndK   = 0x54 // BPF_ALU | BPF_AND | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K

	seccompDataNROff   = 0          // offset of seccomp_data.nr
	seccompDataArchOff = 4          // offset of seccomp_data.arch
	seccompDataArg0Off = 16         // offset of seccomp_data.args[0] (low 32 bits, x86-64 LE)
	cloneNewNamespaces = 0x7E020000 // CLONE_NEW{NS,CGROUP,UTS,IPC,USER,PID,NET} OR-mask
)

// seccompAllow is the syscall allowlist (amd64). Curated to run the pinned tools (Go
// runtime + git/C) while omitting privilege/escape/observe syscalls. Erring toward
// inclusion of benign runtime syscalls; every omission is a deliberate deny.
var seccompAllow = []int{
	// file + descriptor I/O
	unix.SYS_READ, unix.SYS_WRITE, unix.SYS_OPEN, unix.SYS_OPENAT, unix.SYS_OPENAT2,
	unix.SYS_CLOSE, unix.SYS_CLOSE_RANGE, unix.SYS_LSEEK, unix.SYS_PREAD64, unix.SYS_PWRITE64,
	unix.SYS_READV, unix.SYS_WRITEV, unix.SYS_PIPE, unix.SYS_PIPE2, unix.SYS_DUP, unix.SYS_DUP2,
	unix.SYS_DUP3, unix.SYS_FCNTL, unix.SYS_FLOCK, unix.SYS_FSYNC, unix.SYS_FDATASYNC,
	unix.SYS_FTRUNCATE, unix.SYS_TRUNCATE, unix.SYS_FALLOCATE, unix.SYS_SENDFILE,
	unix.SYS_COPY_FILE_RANGE, unix.SYS_SPLICE, unix.SYS_TEE, unix.SYS_SYNC, unix.SYS_SYNCFS,
	unix.SYS_FADVISE64, unix.SYS_READAHEAD,
	// stat / metadata
	unix.SYS_STAT, unix.SYS_FSTAT, unix.SYS_LSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STATX,
	unix.SYS_STATFS, unix.SYS_FSTATFS, unix.SYS_ACCESS, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2,
	unix.SYS_GETDENTS, unix.SYS_GETDENTS64, unix.SYS_GETCWD, unix.SYS_READLINK, unix.SYS_READLINKAT,
	// directory / link mutation (within the writable workdir)
	unix.SYS_CHDIR, unix.SYS_FCHDIR, unix.SYS_RENAME, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2,
	unix.SYS_MKDIR, unix.SYS_MKDIRAT, unix.SYS_RMDIR, unix.SYS_CREAT, unix.SYS_LINK, unix.SYS_LINKAT,
	unix.SYS_UNLINK, unix.SYS_UNLINKAT, unix.SYS_SYMLINK, unix.SYS_SYMLINKAT,
	unix.SYS_CHMOD, unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_CHOWN, unix.SYS_FCHOWN,
	unix.SYS_LCHOWN, unix.SYS_FCHOWNAT, unix.SYS_UMASK, unix.SYS_UTIME, unix.SYS_UTIMES,
	unix.SYS_UTIMENSAT, unix.SYS_FUTIMESAT,
	// memory
	unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_MREMAP, unix.SYS_MSYNC,
	unix.SYS_MINCORE, unix.SYS_MADVISE, unix.SYS_BRK, unix.SYS_MLOCK, unix.SYS_MUNLOCK,
	// signals
	unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGPENDING,
	unix.SYS_RT_SIGTIMEDWAIT, unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_SIGSUSPEND, unix.SYS_SIGALTSTACK,
	unix.SYS_KILL, unix.SYS_TGKILL, unix.SYS_TKILL, unix.SYS_PAUSE,
	// process lifecycle / threads – NOTE: clone + clone3 are handled specially in
	// buildSeccompProgram (flag-filtered to block CLONE_NEW*), NOT listed here.
	unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_EXIT,
	unix.SYS_EXIT_GROUP, unix.SYS_WAIT4, unix.SYS_WAITID, unix.SYS_SET_TID_ADDRESS,
	unix.SYS_SET_ROBUST_LIST, unix.SYS_GET_ROBUST_LIST, unix.SYS_RSEQ, unix.SYS_GETPID,
	unix.SYS_GETPPID, unix.SYS_GETTID, unix.SYS_GETPGRP, unix.SYS_GETPGID, unix.SYS_SETPGID,
	unix.SYS_SETSID, unix.SYS_GETSID, unix.SYS_PRCTL, unix.SYS_ARCH_PRCTL, unix.SYS_RESTART_SYSCALL,
	// scheduling / time
	unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY, unix.SYS_SCHED_SETAFFINITY,
	unix.SYS_SCHED_GETPARAM, unix.SYS_SCHED_GETSCHEDULER, unix.SYS_SCHED_GET_PRIORITY_MAX,
	unix.SYS_SCHED_GET_PRIORITY_MIN, unix.SYS_GETPRIORITY, unix.SYS_SETPRIORITY,
	unix.SYS_NANOSLEEP, unix.SYS_CLOCK_NANOSLEEP, unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_GETRES,
	unix.SYS_GETTIMEOFDAY, unix.SYS_TIME, unix.SYS_TIMES, unix.SYS_GETITIMER, unix.SYS_SETITIMER,
	// futex / polling / events
	unix.SYS_FUTEX, unix.SYS_FUTEX_WAITV, unix.SYS_POLL, unix.SYS_PPOLL, unix.SYS_SELECT,
	unix.SYS_PSELECT6, unix.SYS_EPOLL_CREATE, unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL,
	unix.SYS_EPOLL_WAIT, unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_PWAIT2, unix.SYS_EVENTFD,
	unix.SYS_EVENTFD2, unix.SYS_SIGNALFD, unix.SYS_SIGNALFD4, unix.SYS_TIMERFD_CREATE,
	unix.SYS_TIMERFD_SETTIME, unix.SYS_TIMERFD_GETTIME,
	// network (TCP/UDP – NOT raw; AF_PACKET blocked by dropping CAP_NET_RAW)
	unix.SYS_SOCKET, unix.SYS_CONNECT, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_BIND,
	unix.SYS_LISTEN, unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_SOCKETPAIR,
	unix.SYS_SETSOCKOPT, unix.SYS_GETSOCKOPT, unix.SYS_SENDTO, unix.SYS_RECVFROM,
	unix.SYS_SENDMSG, unix.SYS_RECVMSG, unix.SYS_SENDMMSG, unix.SYS_RECVMMSG, unix.SYS_SHUTDOWN,
	// identity / limits / info
	unix.SYS_GETUID, unix.SYS_GETGID, unix.SYS_GETEUID, unix.SYS_GETEGID, unix.SYS_GETGROUPS,
	unix.SYS_GETRESUID, unix.SYS_GETRESGID, unix.SYS_GETRLIMIT, unix.SYS_PRLIMIT64,
	unix.SYS_GETRUSAGE, unix.SYS_SYSINFO, unix.SYS_UNAME, unix.SYS_GETCPU, unix.SYS_CAPGET,
	// randomness / fds / misc runtime
	unix.SYS_GETRANDOM, unix.SYS_MEMFD_CREATE, unix.SYS_MEMBARRIER,
	unix.SYS_INOTIFY_INIT, unix.SYS_INOTIFY_INIT1, unix.SYS_INOTIFY_ADD_WATCH,
	unix.SYS_INOTIFY_RM_WATCH, unix.SYS_IOCTL,
}

// buildSeccompProgram emits the raw cBPF program bytes for the filter above.
func buildSeccompProgram() []byte {
	var b bytes.Buffer
	emit := func(code uint16, jt, jf uint8, k uint32) {
		_ = binary.Write(&b, binary.LittleEndian, code)
		b.WriteByte(jt)
		b.WriteByte(jf)
		_ = binary.Write(&b, binary.LittleEndian, k)
	}
	// Validate architecture: a foreign-arch syscall (e.g. x32) is KILLED, not just denied.
	emit(bpfLdWAbs, 0, 0, seccompDataArchOff)
	emit(bpfJeqK, 1, 0, auditArchX8664) // arch == x86_64 ? skip the kill: fall through
	emit(bpfRetK, 0, 0, seccompRetKillProcess)
	emit(bpfLdWAbs, 0, 0, seccompDataNROff) // accumulator = syscall nr

	// clone3 (struct-arg → un-filterable in cBPF): return ENOSYS so glibc falls back to the
	// legacy clone, which IS flag-filtered below. (Go's runtime uses clone directly.)
	emit(bpfJeqK, 0, 1, uint32(unix.SYS_CLONE3)) // nr==clone3 ? fall to ENOSYS: skip
	emit(bpfRetK, 0, 0, seccompRetErrnoENOSYS)

	// clone: ALLOW only when no CLONE_NEW* namespace flag is set – blocks a tool from
	// creating a nested user/mount/net/etc. namespace (the demonstrated nested-userns
	// escape-surface). Go/glibc thread creation sets none of these flags, so it is allowed.
	emit(bpfJeqK, 0, 5, uint32(unix.SYS_CLONE)) // nr==clone ? fall into the 5-instr check: skip past it
	emit(bpfLdWAbs, 0, 0, seccompDataArg0Off)   // accumulator = clone flags (args[0] low word)
	emit(bpfAndK, 0, 0, cloneNewNamespaces)     // mask the CLONE_NEW* bits
	emit(bpfJeqK, 0, 1, 0)                      // (flags & NEW*)==0 ? fall to ALLOW: skip to DENY
	emit(bpfRetK, 0, 0, seccompRetAllow)        // no namespace flag → allow (normal thread clone)
	emit(bpfRetK, 0, 0, seccompRetErrnoEPERM)   // CLONE_NEW* requested → deny

	// Flat allowlist (2 instrs each, jumps of 0/1 so offsets never overflow u8 jt/jf).
	for _, nr := range seccompAllow {
		emit(bpfJeqK, 0, 1, uint32(nr)) // nr == X ? fall to ALLOW: skip it
		emit(bpfRetK, 0, 0, seccompRetAllow)
	}
	emit(bpfRetK, 0, 0, seccompRetErrnoEPERM) // default: deny with EPERM
	return b.Bytes()
}

// seccompFile writes the compiled filter to an unlinked temp file and returns it open at
// offset 0, ready to pass to bwrap as an inherited fd (--seccomp). The caller closes it
// after the run. Unlinking immediately means the bytes live only as long as the open fd.
func seccompFile() (*os.File, error) {
	f, err := os.CreateTemp("", "synapse-seccomp-*.bpf")
	if err != nil {
		return nil, err
	}
	_ = os.Remove(f.Name()) // unlink; the open fd keeps it readable
	if _, err := f.Write(buildSeccompProgram()); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// seccompSupported reports that seccomp filtering can be built on this platform.
const seccompSupported = true
