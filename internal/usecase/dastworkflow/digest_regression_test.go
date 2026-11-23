package dastworkflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/agent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestProbeDigestSeparatesNewlineFields(t *testing.T) {
	a := dastrunner.Probe{JudgmentID: "judgment", URL: "https://example.com", ExpectedBodyContains: "marker\n1", ScoreIfConfirmed: 2, ScoreIfRefuted: 3, ExpectedVersion: 4, Rationale: "reason"}
	b := dastrunner.Probe{JudgmentID: "judgment", URL: "https://example.com", ExpectedBodyContains: "marker", ScoreIfConfirmed: 1, ScoreIfRefuted: 2, ExpectedVersion: 3, Rationale: "4\nreason"}
	if probeDigest(a, "GET") == probeDigest(b, "GET") {
		t.Fatal("distinct approved probe configurations share a digest")
	}
}

// Legacy newline-joined approvals must not authorize a newly structured probe.
type legacyDigestStore struct {
	ports.ApprovalStore
	legacy string
}

func (s legacyDigestStore) Get(ctx context.Context, id shared.ID) (agent.ProposedAction, agent.ApprovalDecision, error) {
	a, d, err := s.ApprovalStore.Get(ctx, id)
	if err == nil {
		a.Argv[1] = "--config-sha256=" + s.legacy
	}
	return a, d, err
}
func TestLegacyApprovalDigestFailsClosed(t *testing.T) {
	runner := &fakeRunner{}
	wf, store := workflowForTest(t, runner, &fakeApplier{})
	p := testProbe()
	prop, err := wf.Propose(context.Background(), "alice", "eng-1", p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wf.Decide(context.Background(), "bob", "eng-1", prop.Action.ID, true, "ok"); err != nil {
		t.Fatal(err)
	}
	raw := strings.Join([]string{p.JudgmentID.String(), p.URL, p.NormalizedMethod(), fmt.Sprint(p.ExpectedStatus), p.ExpectedBodyContains, fmt.Sprint(p.ScoreIfConfirmed), fmt.Sprint(p.ScoreIfRefuted), fmt.Sprint(p.ExpectedVersion), p.Rationale}, "\n")
	digest := sha256.Sum256([]byte(raw))
	wf.store = legacyDigestStore{store, hex.EncodeToString(digest[:])}
	if _, err := wf.Run(context.Background(), "alice", "eng-1", prop.Action.ID, p); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("legacy approval accepted: %v", err)
	}
	if runner.calls != 0 {
		t.Fatal("tool ran with legacy approval")
	}
}
