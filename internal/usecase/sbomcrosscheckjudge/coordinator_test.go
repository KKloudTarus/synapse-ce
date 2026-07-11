package sbomcrosscheckjudge

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/judgment"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeProposer struct {
	existing []judgment.Judgment
	proposed []judgment.Judgment
	failAt   int // 1-based; fail the Nth Propose
	n        int
}

func (f *fakeProposer) List(context.Context, shared.ID) ([]judgment.Judgment, error) {
	return f.existing, nil
}
func (f *fakeProposer) Propose(_ context.Context, proposer string, eng shared.ID, cap judgment.Capability, sk judgment.SubjectKind, sid shared.ID, claim judgment.Claim) (judgment.Judgment, error) {
	f.n++
	if f.failAt != 0 && f.n == f.failAt {
		return judgment.Judgment{}, errors.New("propose boom")
	}
	j := judgment.Judgment{ID: shared.ID("j-" + strconv.Itoa(f.n)), EngagementID: eng, Capability: cap, SubjectKind: sk, SubjectID: sid, Claim: claim, ProposedBy: proposer, State: judgment.StateProposed}
	f.proposed = append(f.proposed, j)
	return j, nil
}

type fakeAudit struct{ entries []ports.AuditEntry }

func (a *fakeAudit) Record(_ context.Context, e ports.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func item(name, version, purl string, reporters, missing []string) sbom.CrossCheckItem {
	return sbom.CrossCheckItem{Name: name, Version: version, PURL: purl, Reporters: reporters, Missing: missing}
}
func report(items ...sbom.CrossCheckItem) sbom.CrossCheckReport {
	return sbom.CrossCheckReport{Disagreements: items}
}

func TestRecordMintsPerDisagreement(t *testing.T) {
	fp, au := &fakeProposer{}, &fakeAudit{}
	c, err := NewCoordinator(fp, au, fixedClock{})
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Record(context.Background(), "eng-1", report(
		item("ms", "2.1.3", "pkg:npm/ms@2.1.3", []string{"syft"}, []string{"ownsbom"}),
		item("acme", "1.0", "", []string{"syft"}, []string{"ownsbom"}), // no PURL → name@version identity
	))
	if err != nil || n != 2 || len(fp.proposed) != 2 {
		t.Fatalf("want 2 minted, got n=%d proposed=%d err=%v", n, len(fp.proposed), err)
	}
	p := fp.proposed[0]
	if p.Capability != judgment.CapCorrelation || p.SubjectKind != judgment.SubjectComponent || p.ProposedBy != "system:sbom-cross-check" {
		t.Fatalf("propose wiring wrong: %+v", p)
	}
	if p.SubjectID != "component:pkg:npm/ms@2.1.3" {
		t.Errorf("subject id must be component:<ComponentID>: %q", p.SubjectID)
	}
	if fp.proposed[1].SubjectID != "component:acme@1.0" {
		t.Errorf("no-PURL subject must fall back to name@version: %q", fp.proposed[1].SubjectID)
	}
	cc, ok := p.Claim.(judgment.CorrelationClaim)
	if !ok || !reflect.DeepEqual(cc.Reporters, []string{"syft"}) || !reflect.DeepEqual(cc.Missing, []string{"ownsbom"}) {
		t.Errorf("claim built wrong: %#v", p.Claim)
	}
	if len(au.entries) != 2 || au.entries[0].Action != "judgment.sbom_correlation_proposed" {
		t.Errorf("each mint must be audited with the sbom action, got %+v", au.entries)
	}
}

func TestRecordIdempotent(t *testing.T) {
	fp := &fakeProposer{existing: []judgment.Judgment{{Capability: judgment.CapCorrelation, SubjectKind: judgment.SubjectComponent, SubjectID: "component:pkg:npm/ms@2.1.3"}}}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, _ := c.Record(context.Background(), "eng-1", report(
		item("ms", "2.1.3", "pkg:npm/ms@2.1.3", []string{"syft"}, []string{"ownsbom"}), // already recorded → skip
		item("acme", "1.0", "pkg:npm/acme@1.0", []string{"syft"}, []string{"ownsbom"}), // new → mint
	))
	if n != 1 || len(fp.proposed) != 1 || fp.proposed[0].SubjectID != "component:pkg:npm/acme@1.0" {
		t.Fatalf("must skip the already-recorded subject, mint only the new: n=%d proposed=%+v", n, fp.proposed)
	}
}

func TestVulnCorrelationDoesNotSuppressComponent(t *testing.T) {
	// A vulnerability-correlation judgment (same CapCorrelation) with a colliding subject id must NOT
	// suppress a COMPONENT disagreement – the dedup filters on SubjectKind==component too.
	fp := &fakeProposer{existing: []judgment.Judgment{{Capability: judgment.CapCorrelation, SubjectKind: judgment.SubjectVulnerability, SubjectID: "component:pkg:npm/ms@2.1.3"}}}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, _ := c.Record(context.Background(), "eng-1", report(
		item("ms", "2.1.3", "pkg:npm/ms@2.1.3", []string{"syft"}, []string{"ownsbom"}),
	))
	if n != 1 {
		t.Fatalf("a vuln-correlation judgment must not suppress a component disagreement; got n=%d", n)
	}
}

func TestRecordDeduplicatesWithinReport(t *testing.T) {
	fp := &fakeProposer{}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, _ := c.Record(context.Background(), "eng-1", report(
		item("ms", "2.1.3", "pkg:npm/ms@2.1.3", []string{"syft"}, []string{"ownsbom"}),
		item("ms", "2.1.3", "pkg:npm/ms@2.1.3", []string{"grype"}, []string{"ownsbom"}), // same subject id
	))
	if n != 1 || len(fp.proposed) != 1 {
		t.Fatalf("a duplicate subject within one report must mint once, got n=%d", n)
	}
}

func TestRecordSkipsBlankComponent(t *testing.T) {
	fp := &fakeProposer{}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, err := c.Record(context.Background(), "eng-1", report(
		item("", "", "", []string{"syft"}, []string{"ownsbom"}),                        // blank → no subject → skipped
		item("ms", "2.1.3", "pkg:npm/ms@2.1.3", []string{"syft"}, []string{"ownsbom"}), // minted
	))
	if err != nil || n != 1 || len(fp.proposed) != 1 || fp.proposed[0].SubjectID != "component:pkg:npm/ms@2.1.3" {
		t.Fatalf("a blank component must be skipped (only ms minted): n=%d proposed=%+v", n, fp.proposed)
	}
}

func TestRecordNoDisagreements(t *testing.T) {
	fp := &fakeProposer{}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, err := c.Record(context.Background(), "eng-1", sbom.CrossCheckReport{})
	if err != nil || n != 0 || len(fp.proposed) != 0 {
		t.Fatalf("no disagreements → 0 minted, no propose; got n=%d err=%v", n, err)
	}
}

func TestRecordProposeErrorAborts(t *testing.T) {
	fp := &fakeProposer{failAt: 2}
	c, _ := NewCoordinator(fp, &fakeAudit{}, fixedClock{})
	n, err := c.Record(context.Background(), "eng-1", report(
		item("a", "1", "pkg:npm/a@1", []string{"syft"}, []string{"ownsbom"}),
		item("b", "2", "pkg:npm/b@2", []string{"syft"}, []string{"ownsbom"}),
	))
	if err == nil || n != 1 {
		t.Fatalf("a propose error must abort with the partial count 1, got n=%d err=%v", n, err)
	}
}

func TestRecordRequiresEngagement(t *testing.T) {
	c, _ := NewCoordinator(&fakeProposer{}, &fakeAudit{}, fixedClock{})
	if _, err := c.Record(context.Background(), "", report(item("a", "1", "pkg:npm/a@1", []string{"syft"}, []string{"ownsbom"}))); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("empty engagement must be rejected, got %v", err)
	}
}

func TestNewCoordinatorValidates(t *testing.T) {
	if _, err := NewCoordinator(nil, &fakeAudit{}, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil proposer must fail")
	}
	if _, err := NewCoordinator(&fakeProposer{}, nil, fixedClock{}); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil audit must fail")
	}
	if _, err := NewCoordinator(&fakeProposer{}, &fakeAudit{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Error("nil clock must fail")
	}
}
