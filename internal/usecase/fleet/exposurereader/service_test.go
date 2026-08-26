package exposurereader

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityoccurrence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityrisk"
)

type fakeMembership struct {
	engs      []*engagement.Engagement
	projects  []asset.ComponentMembership
	technical []asset.ComponentMembership
	engErr    error
	projErr   error
	techErr   error
}

func (m fakeMembership) ListEngagementsByBusinessAsset(_ context.Context, _, _ shared.ID) ([]*engagement.Engagement, error) {
	return m.engs, m.engErr
}
func (m fakeMembership) ListBusinessAssetProjects(_ context.Context, _, _ shared.ID) ([]asset.ComponentMembership, error) {
	return m.projects, m.projErr
}
func (m fakeMembership) ListBusinessAssetTechnicalAssets(_ context.Context, _, _ shared.ID) ([]asset.ComponentMembership, error) {
	return m.technical, m.techErr
}

type fakeOccurrences struct {
	byEng     map[shared.ID][]vulnerabilityoccurrence.Occurrence
	err       error
	gotStates []vulnerabilityoccurrence.State
}

func (o *fakeOccurrences) ListByEngagement(_ context.Context, _, engagementID shared.ID, states []vulnerabilityoccurrence.State) ([]vulnerabilityoccurrence.Occurrence, error) {
	o.gotStates = states
	return o.byEng[engagementID], o.err
}

type fakeRisk struct {
	byOcc map[shared.ID]vulnerabilityrisk.Assessment
	err   error
}

func (r fakeRisk) Current(_ context.Context, _, occurrenceID shared.ID) (vulnerabilityrisk.Assessment, error) {
	if r.err != nil {
		return vulnerabilityrisk.Assessment{}, r.err
	}
	a, ok := r.byOcc[occurrenceID]
	if !ok {
		return vulnerabilityrisk.Assessment{}, shared.ErrNotFound
	}
	return a, nil
}

func ctxT() context.Context { return shared.WithTenant(context.Background(), "t1") }

func member(comp string) asset.ComponentMembership {
	return asset.ComponentMembership{TenantID: "t1", AssetID: "asset-1", ComponentID: shared.ID(comp), Role: asset.MembershipRole("dependency")}
}
func occ(id, comp, adv string) vulnerabilityoccurrence.Occurrence {
	return vulnerabilityoccurrence.Occurrence{TenantID: "t1", ID: shared.ID(id), EngagementID: "eng-1", AdvisoryID: adv, ComponentID: shared.ID(comp), State: vulnerabilityoccurrence.StateDetected}
}
func assess(pri int, kev bool) vulnerabilityrisk.Assessment {
	return vulnerabilityrisk.Assessment{Severity: shared.SeverityHigh, Priority: pri, KEV: kev}
}

func mustReader(t *testing.T, m MembershipReader, o OccurrenceReader, r RiskReader) *Reader {
	t.Helper()
	rd, err := NewReader(m, o, r)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	return rd
}

func oneEngagement() []*engagement.Engagement { return []*engagement.Engagement{{ID: "eng-1"}} }

func TestAbstainNoEngagements(t *testing.T) {
	rd := mustReader(t, fakeMembership{engs: nil}, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("no engagements must abstain with ErrNotFound, got %v", err)
	}
}

func TestAbstainNoComponents(t *testing.T) {
	rd := mustReader(t, fakeMembership{engs: oneEngagement()}, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("no component inventory must abstain with ErrNotFound, got %v", err)
	}
}

func TestScannedCleanReturnsEmpty(t *testing.T) {
	m := fakeMembership{engs: oneEngagement(), projects: []asset.ComponentMembership{member("c1")}}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{}} // no open occurrences
	rd := mustReader(t, m, occs, fakeRisk{})
	got, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("scanned-clean must return empty (nil,nil semantics), got %+v", got)
	}
	// It queried for the open (detected) state only.
	if len(occs.gotStates) != 1 || occs.gotStates[0] != vulnerabilityoccurrence.StateDetected {
		t.Fatalf("must query only StateDetected, got %v", occs.gotStates)
	}
}

func TestJoinFiltersToAssetComponentsAndMapsRisk(t *testing.T) {
	m := fakeMembership{engs: oneEngagement(), projects: []asset.ComponentMembership{member("c1")}, technical: []asset.ComponentMembership{member("c2")}}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{
		"eng-1": {
			occ("o1", "c1", "CVE-1"), // member -> included
			occ("o2", "c2", "CVE-2"), // member -> included
			occ("o3", "c9", "CVE-9"), // NOT a member -> filtered out
			occ("o4", "c1", "CVE-4"), // member, no risk assessment -> skipped
		},
	}}
	risk := fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{
		"o1": assess(1, true),
		"o2": assess(3, false),
		// o4 intentionally absent -> Current returns ErrNotFound -> skipped
	}}
	rd := mustReader(t, m, occs, risk)
	got, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 vulnerable components (c1,c2), got %d: %+v", len(got), got)
	}
	// Deterministic order by component id: c1 then c2.
	if got[0].ComponentID != "c1" || got[0].AdvisoryID != "CVE-1" || got[0].Priority != 1 || !got[0].KEV || got[0].Running {
		t.Fatalf("c1 entry wrong: %+v", got[0])
	}
	if got[1].ComponentID != "c2" || got[1].Priority != 3 {
		t.Fatalf("c2 entry wrong: %+v", got[1])
	}
}

func TestDedupKeepsWorstRiskAcrossEngagements(t *testing.T) {
	m := fakeMembership{
		engs:     []*engagement.Engagement{{ID: "eng-1"}, {ID: "eng-2"}},
		projects: []asset.ComponentMembership{member("c1")},
	}
	o1 := occ("o1", "c1", "CVE-1")
	o1b := occ("o1b", "c1", "CVE-1")
	o1b.EngagementID = "eng-2"
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{
		"eng-1": {o1},
		"eng-2": {o1b},
	}}
	// Divergent risk for the same (component, advisory): eng-1 sees a mild P3 non-KEV, eng-2 a P1 KEV.
	// The dedup must keep the WORST (P1 KEV) so the exposure factor is never under-reported.
	risk := fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{
		"o1":  assess(3, false),
		"o1b": assess(1, true),
	}}
	rd := mustReader(t, m, occs, risk)
	got, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("same (component,advisory) across engagements must dedup to 1, got %d", len(got))
	}
	if got[0].Priority != 1 || !got[0].KEV {
		t.Fatalf("dedup must keep the worst risk (P1 KEV), got %+v", got[0])
	}
}

func TestAbstainWhenAllOccurrencesUnscored(t *testing.T) {
	m := fakeMembership{engs: oneEngagement(), projects: []asset.ComponentMembership{member("c1")}}
	// Detected occurrence on a member component, but no risk assessment exists for it yet.
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{"eng-1": {occ("o1", "c1", "CVE-1")}}}
	rd := mustReader(t, m, occs, fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{}})
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("all-unscored detected occurrences must abstain (ErrNotFound), not read as clean, got %v", err)
	}
}

func TestValidationAndErrorPropagation(t *testing.T) {
	if _, err := NewReader(nil, &fakeOccurrences{}, fakeRisk{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil membership rejected")
	}
	rd := mustReader(t, fakeMembership{engs: oneEngagement(), projects: []asset.ComponentMembership{member("c1")}}, &fakeOccurrences{}, fakeRisk{})
	// no tenant in ctx
	if _, err := rd.ListAssetVulnerableComponents(context.Background(), "asset-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing tenant rejected")
	}
	// empty asset id
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("empty asset id rejected")
	}
	// occurrence store error propagates
	boom := errors.New("db down")
	rd2 := mustReader(t, fakeMembership{engs: oneEngagement(), projects: []asset.ComponentMembership{member("c1")}}, &fakeOccurrences{err: boom}, fakeRisk{})
	if _, err := rd2.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, boom) {
		t.Fatalf("occurrence error must propagate, got %v", err)
	}
	// risk store non-NotFound error propagates
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{"eng-1": {occ("o1", "c1", "CVE-1")}}}
	rd3 := mustReader(t, fakeMembership{engs: oneEngagement(), projects: []asset.ComponentMembership{member("c1")}}, occs, fakeRisk{err: boom})
	if _, err := rd3.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, boom) {
		t.Fatalf("risk error must propagate, got %v", err)
	}
	// membership (engagements) error propagates
	rd4 := mustReader(t, fakeMembership{engErr: boom}, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd4.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, boom) {
		t.Fatalf("engagement lookup error must propagate, got %v", err)
	}
}
