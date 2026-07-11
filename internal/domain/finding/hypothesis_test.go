package finding

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

var hClock = time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)

func validHypothesis(t *testing.T) Finding {
	t.Helper()
	f, err := NewHypothesis("hyp:1", "eng:1", HypothesisInput{
		Title:          "SSRF → metadata creds → lateral move",
		Description:    "The SSRF reaches the cloud metadata endpoint; the leaked role then unlocks the admin API.",
		ConstituentIDs: []string{"find:ssrf", "find:metadata", "find:adminapi"},
	}, "agent:s1", hClock)
	if err != nil {
		t.Fatalf("NewHypothesis valid: %v", err)
	}
	return f
}

func TestNewHypothesisShape(t *testing.T) {
	f := validHypothesis(t)
	if f.Kind != KindHypothesis {
		t.Errorf("kind = %q, want hypothesis", f.Kind)
	}
	if f.ProposedBy != "agent:s1" {
		t.Errorf("ProposedBy must be set (gating anchor), got %q", f.ProposedBy)
	}
	if f.EvidenceScore != 0 || f.Status != StatusOpen || f.Severity != shared.SeverityUnknown {
		t.Errorf("unexpected initial state: score=%d status=%q sev=%q", f.EvidenceScore, f.Status, f.Severity)
	}
	if f.Class != ClassFirstParty {
		t.Errorf("class = %q, want first-party", f.Class)
	}
	// constituent ids are folded into the description (sorted), and anchor the dedup key.
	if !strings.Contains(f.Description, "find:adminapi, find:metadata, find:ssrf") {
		t.Errorf("constituent ids not folded into description: %q", f.Description)
	}
	if f.DedupKey != "hypothesis:find:adminapi,find:metadata,find:ssrf" {
		t.Errorf("dedup key not the sorted constituent set: %q", f.DedupKey)
	}
}

func TestNewHypothesisNonPublishableUntilVerified(t *testing.T) {
	f := validHypothesis(t)
	// A proposed hypothesis is evidence-gated (ProposedBy set) and starts at score 0 → not publishable.
	if !f.RequiresEvidenceGate() {
		t.Error("a hypothesis must require the evidence gate (ProposedBy is set)")
	}
	if f.CanPromote() {
		t.Error("a score-0 hypothesis must NOT be promotable/publishable")
	}
	if got := Publishable([]Finding{f}); len(got) != 0 {
		t.Errorf("a proposed hypothesis must be filtered out of the report, got %d", len(got))
	}
	// Raising the score to the bar (what a future human-verify path will do – the wiring is a follow-up,
	// see the NewHypothesis doc) flips it to promotable: the gate keys purely on EvidenceScore, so a
	// hypothesis is never PERMANENTLY blocked – only pending a verify path that can raise its score.
	f.EvidenceScore = EvidenceThreshold
	if !f.CanPromote() {
		t.Error("a hypothesis at the evidence bar must be promotable (the gate keys on score)")
	}
}

func TestNewHypothesisFailClosed(t *testing.T) {
	base := HypothesisInput{Title: "t", Description: "d", ConstituentIDs: []string{"a", "b"}}
	cases := []struct {
		name     string
		mutate   func(*HypothesisInput)
		proposer string
	}{
		{"no title", func(in *HypothesisInput) { in.Title = "  " }, "agent:s1"},
		{"no description", func(in *HypothesisInput) { in.Description = "" }, "agent:s1"},
		{"no proposer", func(in *HypothesisInput) {}, "  "},
		{"zero constituents", func(in *HypothesisInput) { in.ConstituentIDs = nil }, "agent:s1"},
		{"one constituent", func(in *HypothesisInput) { in.ConstituentIDs = []string{"a"} }, "agent:s1"},
		{"dupes collapse below two", func(in *HypothesisInput) { in.ConstituentIDs = []string{"a", "a", " a "} }, "agent:s1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			in.ConstituentIDs = append([]string{}, base.ConstituentIDs...)
			c.mutate(&in)
			if _, err := NewHypothesis("hyp:1", "eng:1", in, c.proposer, hClock); !errors.Is(err, shared.ErrValidation) {
				t.Errorf("want ErrValidation, got %v", err)
			}
		})
	}
}

func TestHypothesisKindValid(t *testing.T) {
	if !KindHypothesis.Valid() {
		t.Error("KindHypothesis must be a valid kind")
	}
}
