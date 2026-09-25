package toolrunner

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// A failure to initialize a started run must be reported as itself, not as the timeout it causes.
//
// Started runs after the process is up: the egress path uses it to build the network namespace and
// then release a child that is blocked on a pipe. When it fails the child is never released, and a
// run wrapped in `systemd-run --scope` outlives Cancel() because the scope keeps its children, so
// the deadline is reached. Checking the deadline first reported "exceeded its 30s timeout" and
// discarded the reason, which made an egress setup failure look like a slow tool.
func TestStartedErrorIsReportedOverTheTimeoutItCauses(t *testing.T) {
	r := NewExecRunner(30*time.Second, 1<<20)
	sentinel := errors.New("egress netns setup: no route to the allow-list host")

	// Initialization that outlives the deadline before failing is the real shape: building the
	// network namespace is what takes the time, and the child it would release stays blocked
	// meanwhile. Both conditions are then true at once, which is the case the ordering decides.
	res, runErr := r.Run(context.Background(), ports.ToolSpec{
		Name:    "sh",
		Args:    []string{"-c", "sleep 30"},
		Timeout: 400 * time.Millisecond,
		Started: func(ctx context.Context) error {
			<-ctx.Done()
			return sentinel
		},
	})

	if runErr == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(runErr, sentinel) {
		t.Fatalf("error = %v, want it to wrap the initialization failure", runErr)
	}
	if strings.Contains(runErr.Error(), "exceeded its") {
		t.Fatalf("error = %v, want the cause rather than the timeout it produced", runErr)
	}
	// The deadline was still reached, and callers that branch on it must still see that.
	if !res.TimedOut {
		t.Fatal("TimedOut = false, want the deadline still recorded")
	}
}

// A run that simply outlives its timeout, with no initialization failure, still reports the timeout.
func TestTimeoutIsStillReportedWithoutAStartedError(t *testing.T) {
	r := NewExecRunner(30*time.Second, 1<<20)
	res, runErr := r.Run(context.Background(), ports.ToolSpec{
		Name:    "sh",
		Args:    []string{"-c", "sleep 30"},
		Timeout: 900 * time.Millisecond,
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "exceeded its") {
		t.Fatalf("error = %v, want the timeout", runErr)
	}
	if !res.TimedOut {
		t.Fatal("TimedOut = false, want true")
	}
}
