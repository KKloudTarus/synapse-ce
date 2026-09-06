package emulationexec

import (
	"bytes"
	"context"
	"errors"
	"testing"

	dexploit "github.com/KKloudTarus/synapse-ce/internal/domain/exploitation"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeRunner records the last spec it was asked to run and returns a scripted result.
type fakeRunner struct {
	last   ports.ToolSpec
	result ports.ToolResult
	err    error
	calls  int
}

func (f *fakeRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	f.calls++
	f.last = spec
	return f.result, f.err
}

func TestNewRequiresRunner(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("expected error when runner is nil")
	}
	if _, err := New(&fakeRunner{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteMapsTechniqueToBenignArgv(t *testing.T) {
	cases := []struct {
		technique string
		wantName  string
		wantArgs  []string
	}{
		{"emu.process_discovery", "ps", []string{"-e"}},
		{"emu.system_network_config_discovery", "ip", []string{"addr"}},
		{"emu.dns_beacon_benign", "getent", []string{"hosts", "localhost"}},
		{"emu.credential_file_read", "head", []string{"-c", "1", "/etc/shadow"}},
	}
	for _, c := range cases {
		t.Run(c.technique, func(t *testing.T) {
			fr := &fakeRunner{result: ports.ToolResult{Stdout: []byte("ok"), ExitCode: 0}}
			x, err := New(fr)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			out, err := x.Execute(context.Background(), nil, dexploit.Step{Technique: c.technique})
			if err != nil {
				t.Fatalf("Execute returned error: %v", err)
			}
			if fr.last.Name != c.wantName {
				t.Errorf("argv name = %q, want %q", fr.last.Name, c.wantName)
			}
			if len(fr.last.Args) != len(c.wantArgs) {
				t.Fatalf("args = %v, want %v", fr.last.Args, c.wantArgs)
			}
			for i := range c.wantArgs {
				if fr.last.Args[i] != c.wantArgs[i] {
					t.Errorf("arg[%d] = %q, want %q", i, fr.last.Args[i], c.wantArgs[i])
				}
			}
			if !out.Succeeded {
				t.Errorf("Succeeded = false on exit 0")
			}
			if out.ObservedRadius != offensivepolicy.RadiusReadOnly {
				t.Errorf("ObservedRadius = %q, want read_only", out.ObservedRadius)
			}
			if !bytes.Equal(out.Proof, []byte("ok")) {
				t.Errorf("Proof = %q, want ok", out.Proof)
			}
		})
	}
}

func TestExecuteNonZeroExitIsNotSucceeded(t *testing.T) {
	fr := &fakeRunner{result: ports.ToolResult{Stdout: []byte("boom"), ExitCode: 1}}
	x, _ := New(fr)
	out, err := x.Execute(context.Background(), nil, dexploit.Step{Technique: "emu.process_discovery"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if out.Succeeded {
		t.Error("Succeeded = true on non-zero exit")
	}
}

func TestExecuteUnknownTechniqueIsNotObserved(t *testing.T) {
	fr := &fakeRunner{}
	x, _ := New(fr)
	out, err := x.Execute(context.Background(), nil, dexploit.Step{Technique: "emu.service_restart_probe"})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if fr.calls != 0 {
		t.Errorf("runner invoked for a technique with no benign observable (calls=%d)", fr.calls)
	}
	if out.Succeeded {
		t.Error("Succeeded = true for a technique with no benign observable")
	}
	if out.ObservedRadius != offensivepolicy.RadiusReadOnly {
		t.Errorf("ObservedRadius = %q, want read_only", out.ObservedRadius)
	}
}

func TestExecuteRunnerErrorIsNotObservedNotFatal(t *testing.T) {
	fr := &fakeRunner{err: errors.New("sandbox denied")}
	x, _ := New(fr)
	out, err := x.Execute(context.Background(), nil, dexploit.Step{Technique: "emu.dns_beacon_benign"})
	if err != nil {
		t.Fatalf("Execute must not surface a technique-level failure as an error: %v", err)
	}
	if out.Succeeded {
		t.Error("Succeeded = true when the sandbox refused to run the command")
	}
}

func TestExecuteBoundsProof(t *testing.T) {
	big := bytes.Repeat([]byte("A"), maxProofBytes+512)
	fr := &fakeRunner{result: ports.ToolResult{Stdout: big, ExitCode: 0}}
	x, _ := New(fr)
	out, _ := x.Execute(context.Background(), nil, dexploit.Step{Technique: "emu.process_discovery"})
	if len(out.Proof) > maxProofBytes {
		t.Errorf("Proof len = %d, want <= %d", len(out.Proof), maxProofBytes)
	}
}
