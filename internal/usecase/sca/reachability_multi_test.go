package sca

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeReachRecorder struct {
	minted int
	err    error
	calls  int
}

func (f *fakeReachRecorder) Record(context.Context, shared.ID, string, []ports.ReachabilitySubject) (int, error) {
	f.calls++
	return f.minted, f.err
}

func TestMultiReachabilityRecorderContinuesAfterNoCoverageError(t *testing.T) {
	first := &fakeReachRecorder{minted: 1, err: errors.New("no coverage")}
	second := &fakeReachRecorder{minted: 2}
	multi := &multiReachabilityRecorder{recorders: []ports.ReachabilityRecorder{first, second}}

	n, err := multi.Record(context.Background(), "eng-1", "/work", []ports.ReachabilitySubject{{FindingID: "f-1", Symbols: []string{"vuln.Symbol"}}})
	if n != 3 {
		t.Fatalf("minted=%d, want 3", n)
	}
	if err == nil || err.Error() != "no coverage" {
		t.Fatalf("err=%v, want joined no-coverage error", err)
	}
	if first.calls != 1 || second.calls != 1 {
		t.Fatalf("calls=(%d,%d), want both recorders called once", first.calls, second.calls)
	}
}
