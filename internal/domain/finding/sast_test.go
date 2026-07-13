package finding

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewSAST(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	f, err := NewSAST("f1", "eng1", SASTInput{
		JudgmentID: "j-abc",
		CWE:        "CWE-89",
		Location:   "app/dao.Find",
		Rule:       "taint-sqli",
	}, now)
	if err != nil {
		t.Fatalf("NewSAST: %v", err)
	}
	if f.Kind != KindSAST || f.Class != ClassFirstParty {
		t.Errorf("must be a first-party SAST finding, got kind=%s class=%s", f.Kind, f.Class)
	}
	if f.CWE != "CWE-89" || f.Severity != shared.SeverityUnknown {
		t.Errorf("CWE must carry through; severity defaults to Unknown for human triage: %+v", f)
	}
	if f.DedupKey != "sast:ai:j-abc" {
		t.Errorf("dedup must anchor on the judgment id (distinct from pattern-SAST keys), got %q", f.DedupKey)
	}
	if f.ProposedBy != "" {
		t.Errorf("ProposedBy must be empty (the gate ran at the judgment layer) – else the projection is re-gated stuck-at-0, got %q", f.ProposedBy)
	}
	if f.RuleKey != "taint-sqli" {
		t.Errorf("RuleKey must match the supplied rule, got %q", f.RuleKey)
	}
	// The title is templated from the structured fields (no LLM prose).
	if want := "Taint: taint-sqli (CWE-89) at app/dao.Find"; f.Title != want {
		t.Errorf("title must be templated, want %q got %q", want, f.Title)
	}
}

func TestNewSASTDedupStableAcrossReconfirm(t *testing.T) {
	in := SASTInput{JudgmentID: "j-1", CWE: "CWE-78", Location: "app.run", Rule: "taint-command-injection"}
	a, _ := NewSAST("f1", "eng1", in, time.Unix(0, 0).UTC())
	b, _ := NewSAST("f2", "eng1", in, time.Unix(0, 0).UTC())
	if a.DedupKey != b.DedupKey {
		t.Errorf("the same confirmed judgment must map to the same dedup key (re-confirm updates in place): %q vs %q", a.DedupKey, b.DedupKey)
	}
}

func TestNewSASTValidation(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	cases := map[string]SASTInput{
		"missing cwe":      {JudgmentID: "j", Location: "x", Rule: "r"},
		"missing location": {JudgmentID: "j", CWE: "CWE-89", Rule: "r"},
		"missing rule":     {JudgmentID: "j", CWE: "CWE-89", Location: "x"},
		"missing anchor":   {CWE: "CWE-89", Location: "x", Rule: "r"},
	}
	for name, in := range cases {
		if _, err := NewSAST("f", "eng", in, now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", name, err)
		}
	}
	if _, err := NewSAST("f", "eng", SASTInput{JudgmentID: "j", CWE: "CWE-89", Location: "x", Rule: "r", Severity: shared.Severity("bogus")}, now); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("an invalid severity must be rejected, got %v", err)
	}
}
