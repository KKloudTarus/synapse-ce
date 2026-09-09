package ownadvisory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// EPIC #860 D2.6: a labeled match-quality corpus and a precision/recall gate over the owned matcher.
//
// The advisory unit tests are table tests that each assert one comparator behavior. They cannot prove the
// matcher as a whole competes with Grype/OSV-scanner, nor catch a comparator regression that silently drops
// a real match or invents a false one. This gate runs the WHOLE owned matching path (ownadvisory.Source.Scan
// over a keyed store, i.e. ecosystem derivation, canonical naming, and every ECOSYSTEM/SEMVER comparator)
// against a ground-truth corpus of component@version -> expected advisory ids that includes known-negatives
// (a fixed/higher version, an in-gap version, a wrong release, and an unrelated package), then computes
// precision and recall and fails below a checked-in ratchet.
//
// Ground truth: the language-ecosystem advisories carry REAL published CVE ranges (Log4Shell, the lodash
// prototype-pollution fix, the urllib3 ReDoS fix, the golang.org/x/text out-of-bounds fix). The distro
// entries are construction-correct: whether the component version falls below the fixed bound is decided by
// the dpkg / apk comparator, which is exactly what is under test. A regression in any comparator, ecosystem
// key, or range walk moves a case from the right column to the wrong one and drops the metric below the
// ratchet.

// matchQualityRatchet is the checked-in floor. The curated corpus is chosen so a correct matcher scores a
// perfect 1.0 on both metrics; a comparator regression that misses a real match (recall) or invents a false
// one (precision) drops below this and fails. Raise it only, never lower it (ratchet).
const matchQualityRatchet = 1.0

type corpusFile struct {
	Advisories []json.RawMessage `json:"advisories"`
	Cases      []corpusCase      `json:"cases"`
}

type corpusCase struct {
	Desc     string   `json:"desc"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl"`
	Expected []string `json:"expected"`
}

func loadCorpus(t *testing.T) corpusFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "corpus", "corpus.json"))
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpusFile
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(c.Advisories) == 0 || len(c.Cases) == 0 {
		t.Fatal("corpus must carry advisories and cases")
	}
	return c
}

// corpusStore builds the keyed advisory store from the corpus's real OSV documents, exercising ParseOSV so
// the gate covers the ingest+match path end to end.
func corpusStore(t *testing.T, advs []json.RawMessage) memStore {
	t.Helper()
	byKey := map[string][]advisory.Advisory{}
	for i, raw := range advs {
		adv, err := ParseOSV(raw)
		if err != nil {
			t.Fatalf("parse advisory %d: %v", i, err)
		}
		for _, ap := range adv.Affected {
			key := ap.Ecosystem + "|" + ap.Package
			byKey[key] = append(byKey[key], adv)
		}
	}
	return memStore{byKey: byKey}
}

func TestMatchQualityCorpus(t *testing.T) {
	corpus := loadCorpus(t)
	store := corpusStore(t, corpus.Advisories)
	src := New(store)

	var tp, fp, fn int
	for _, c := range corpus.Cases {
		doc := &sbom.SBOM{Components: []sbom.Component{{Name: c.Name, Version: c.Version, PURL: c.PURL}}}
		raws, err := src.Scan(context.Background(), doc)
		if err != nil {
			t.Fatalf("scan %q: %v", c.Desc, err)
		}
		got := map[string]bool{}
		for _, r := range raws {
			got[r.AdvisoryID] = true
		}
		want := map[string]bool{}
		for _, id := range c.Expected {
			want[id] = true
		}
		// Per-case accounting, and a precise diff so a regression names the offending case.
		for id := range want {
			if got[id] {
				tp++
			} else {
				fn++
				t.Errorf("MISS (recall) case %q: expected advisory %q not matched; got %v", c.Desc, id, sortedSet(got))
			}
		}
		for id := range got {
			if !want[id] {
				fp++
				t.Errorf("FALSE MATCH (precision) case %q: matched unexpected advisory %q; expected %v", c.Desc, id, c.Expected)
			}
		}
	}

	precision := ratio(tp, tp+fp)
	recall := ratio(tp, tp+fn)
	t.Logf("match-quality corpus: cases=%d tp=%d fp=%d fn=%d precision=%.4f recall=%.4f (ratchet %.2f)",
		len(corpus.Cases), tp, fp, fn, precision, recall, matchQualityRatchet)
	if precision < matchQualityRatchet {
		t.Errorf("precision %.4f below ratchet %.2f (a false match regressed the matcher)", precision, matchQualityRatchet)
	}
	if recall < matchQualityRatchet {
		t.Errorf("recall %.4f below ratchet %.2f (a missed match regressed the matcher)", recall, matchQualityRatchet)
	}
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 1.0 // no predictions / no positives on this axis: vacuously perfect, never a false regression
	}
	return float64(num) / float64(den)
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
