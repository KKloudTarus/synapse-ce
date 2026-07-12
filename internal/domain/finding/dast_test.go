package finding

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNewDAST(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	f, err := NewDAST("f1", "eng1", DASTInput{
		JudgmentID: "j-abc",
		CWE:        "CWE-89",
		Location:   "app/dao.Find",
		Rule:       "taint-sqli",
	}, now)
	if err != nil {
		t.Fatalf("NewDAST: %v", err)
	}
	if f.Kind != KindDAST || f.Class != ClassFirstParty {
		t.Errorf("must be a first-party DAST finding, got kind=%s class=%s", f.Kind, f.Class)
	}
	if f.Reachability != "reachable" {
		t.Errorf("a runtime probe proves reachability, want reachable, got %q", f.Reachability)
	}
	if f.CWE != "CWE-89" || f.Severity != shared.SeverityUnknown {
		t.Errorf("CWE must carry through; severity defaults to Unknown for human triage: %+v", f)
	}
	if f.DedupKey != "dast:ai:j-abc" {
		t.Errorf("dedup must anchor on the judgment id (distinct from the SAST projection), got %q", f.DedupKey)
	}
	if f.ProposedBy != "" {
		t.Errorf("ProposedBy must be empty (the gate ran at the judgment layer), got %q", f.ProposedBy)
	}
	// The title is templated from the structured fields (no LLM prose).
	if want := "Runtime-confirmed: taint-sqli (CWE-89) at app/dao.Find"; f.Title != want {
		t.Errorf("title must be templated, want %q got %q", want, f.Title)
	}
}

// The DAST and SAST projections of the SAME judgment must NOT share a dedup key — a claim confirmed
// statically (Kind=sast) and one confirmed at runtime (Kind=dast) are distinct rows.
func TestNewDASTDedupDistinctFromSAST(t *testing.T) {
	in := DASTInput{JudgmentID: "j-1", CWE: "CWE-78", Location: "app.run", Rule: "taint-command-injection"}
	d, _ := NewDAST("f1", "eng1", in, time.Unix(0, 0).UTC())
	s, _ := NewSAST("f2", "eng1", SASTInput{JudgmentID: "j-1", CWE: "CWE-78", Location: "app.run", Rule: "taint-command-injection"}, time.Unix(0, 0).UTC())
	if d.DedupKey == s.DedupKey {
		t.Errorf("DAST and SAST dedup keys must differ, both were %q", d.DedupKey)
	}
	// re-confirm stability: the same runtime judgment maps to the same DAST key.
	d2, _ := NewDAST("f3", "eng1", in, time.Unix(0, 0).UTC())
	if d.DedupKey != d2.DedupKey {
		t.Errorf("the same confirmed judgment must map to the same DAST dedup key, got %q vs %q", d.DedupKey, d2.DedupKey)
	}
}

func TestNewDASTValidation(t *testing.T) {
	now := time.Unix(0, 0).UTC()
	cases := map[string]DASTInput{
		"missing cwe":      {JudgmentID: "j", Location: "x", Rule: "r"},
		"missing location": {JudgmentID: "j", CWE: "CWE-89", Rule: "r"},
		"missing rule":     {JudgmentID: "j", CWE: "CWE-89", Location: "x"},
		"missing anchor":   {CWE: "CWE-89", Location: "x", Rule: "r"},
	}
	for name, in := range cases {
		if _, err := NewDAST("f", "eng", in, now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", name, err)
		}
	}
}
