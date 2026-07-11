package ports

import (
	"context"
	"os"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/recon"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ToolSpec describes a single argv-based tool execution. The command is always run
// as an argv array – never a shell string – and Args must already
// be derived from validated, in-scope data by the caller. Timeout and
// MaxOutputBytes bound the run: the process is killed once Timeout elapses
// and stdout/stderr are truncated once they reach MaxOutputBytes.
type ToolSpec struct {
	Name           string        // binary name (resolved on PATH) or absolute path
	Args           []string      // argv, no shell interpolation
	Stdin          []byte        // optional stdin payload (data, not a command)
	Timeout        time.Duration // 0 = the runner's configured default
	MaxOutputBytes int           // 0 = the runner's configured default cap

	// Sandbox-only fields: the plain ExecRunner ignores these; the
	// SandboxRunner uses them to confine the tool. A zero value means "runner default"
	// / "not requested".
	Workdir       string   // host dir bound read-WRITE inside the sandbox (scoped scratch/output); empty = ephemeral tmpfs only
	ReadOnlyPaths []string // extra host paths bound READ-ONLY (e.g. an acquired source dir, the grype DB)
	CgroupFD      int      // >0: create the process inside this cgroup v2 dir fd (clone-into-cgroup) so the connect-logger captures it; Linux only
	// ExtraFiles are inherited by the child at fd 3, 4, … (index order), mirroring
	// exec.Cmd.ExtraFiles. The SandboxRunner uses this to hand bwrap the seccomp-filter fd
	// (`--seccomp 3`); the caller retains ownership and closes them after Run.
	ExtraFiles []*os.File

	CapAdd      []string // capabilities to re-add after cap-drop ALL (only CAP_NET_RAW, for naabu, is permitted)
	MemMaxBytes int64    // cgroup memory.max via systemd-run (0 = runner default)
	PidsMax     int      // cgroup pids.max via systemd-run (0 = runner default)

	// Env are KEY=VALUE pairs for the child environment. A VALUE may contain a
	// {{secret:NAME}} placeholder: the SandboxRunner resolves it from the credential
	// vault for EngagementID and injects the plaintext via the child's ENVIRONMENT (never
	// argv – so it stays out of `ps`/cmdline), immediately before exec, after the redacted
	// spec was audited + sealed. The plain ExecRunner passes Env through verbatim and does
	// NOT resolve secrets (sandbox-only).
	Env          []string
	EngagementID shared.ID

	// EgressPolicy, when set, makes the SandboxRunner run the tool inside a network
	// namespace whose kernel egress filter is compiled from this policy: the tool
	// can reach only in-scope destinations. Nil = the run is fully network-isolated
	// (bubblewrap's fresh netns, no egress) – the E9 default.
	EgressPolicy *EgressPolicy
	// HostNetwork runs the tool with the HOST network namespace (sandboxed for fs/seccomp/
	// caps/cgroup, but NOT egress-scoped) – used only for acquisition (git/image) when
	// kernel egress scoping is unavailable (F4): it removes the direct-exec surface while
	// still allowing the network the fetch needs. Ignored when EgressPolicy is set
	// (egress-scoped wins). Never set for recon (recon fails closed without egress scoping).
	HostNetwork bool
}

// SecretPlaceholder is the token a ToolSpec uses to reference a vault credential by
// name; the SandboxRunner substitutes the resolved plaintext at exec time.
func SecretPlaceholder(name string) string { return "{{secret:" + name + "}}" }

// ToolResult is the bounded outcome of a ToolSpec run.
type ToolResult struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	TimedOut  bool // the run exceeded its timeout and was killed
	Truncated bool // output reached MaxOutputBytes and was cut
	// ConnectLog is the forensic record of every outbound connect() the tool attempted,
	// captured by the cgroup eBPF hook – populated only for an egress run on the
	// SandboxRunner; nil otherwise. Includes attempts the kernel egress filter DROPPED.
	ConnectLog []ConnEvent
}

// ConnEvent is one outbound connect() attempt observed by the eBPF cgroup hook.
// The hook only observes; Allowed is the verdict computed in userspace against the run's
// egress policy (so a reader sees which attempts the kernel would have / did drop).
type ConnEvent struct {
	PID     uint32 `json:"pid"`
	Family  int    `json:"family"` // 4 | 6
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Allowed bool   `json:"allowed"`
}

// ToolRunner executes argv-based tools with a per-run timeout and output cap. It is
// the single execution primitive for shelled-out tools (argv only).
// The caller MUST authorize the run through the execution guard before calling Run.
type ToolRunner interface {
	Run(ctx context.Context, spec ToolSpec) (ToolResult, error)
}

// ReconTool knows how to drive one recon binary: which target kinds it accepts,
// how to build its argv from an in-scope target (never from free-form strings),
// and how to parse its output into discovered assets. Capability-sensitive tools
// (e.g. naabu/nuclei) are flagged so the use case can hold them behind the
// lab-only / sandbox gate.
type ReconTool interface {
	Name() string                                         // e.g. "subfinder"
	Binary() string                                       // executable name on PATH
	Action() string                                       // gate/audit verb, e.g. "recon.subfinder"
	Accepts(kind engagement.TargetKind) bool              // can it act on this target kind?
	CapabilitySensitive() bool                            // requires elevated caps / sandbox
	BuildArgs(target engagement.Target) (ToolSpec, error) // argv derived from the target
	Parse(stdout []byte) ([]recon.Result, error)          // tool output -> discovered assets
}

// ReconRunStore persists recon-run records (upserted as the run progresses) so the
// UI can list history and resume after a reload.
type ReconRunStore interface {
	Save(ctx context.Context, run recon.Run) error
	Get(ctx context.Context, id shared.ID) (recon.Run, error)
	ListByEngagement(ctx context.Context, engagementID shared.ID) ([]recon.Run, error)
	// ListStaleRunning returns runs still in status 'running' that started before olderThan
	// (bounded by limit) – the input to the stale-run sweeper, which reclaims runs a crashed
	// worker stranded `running` without a dead-letter event (no live owner holds their lease).
	ListStaleRunning(ctx context.Context, olderThan time.Time, limit int) ([]recon.Run, error)
}

// LogEvent is one line on a run's live log stream. ID is a per-run monotonic
// sequence used for SSE reconnect-replay (Last-Event-ID); Done marks end-of-stream.
type LogEvent struct {
	ID   int    `json:"id"`
	Line string `json:"line,omitempty"`
	Done bool   `json:"done,omitempty"`
}

// LogStream is an in-memory pub/sub for run logs with bounded replay, backing the
// SSE endpoint. Publish appends a line (and fans out to live subscribers); Close
// ends the stream; Subscribe replays events after afterID then tails live ones, and
// the returned cancel func unsubscribes. It carries no business logic.
type LogStream interface {
	Publish(runID string, line string)
	Close(runID string)
	Subscribe(runID string, afterID int) (events <-chan LogEvent, cancel func())
}
