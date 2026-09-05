package exposurereader

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/asset"
	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityoccurrence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerabilityrisk"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// The fixtures use ids from the namespaces the schema really produces: business_asset_projects rows carry
// a project id, business_asset_technical_assets rows carry a fleet asset id, engagements carry their own
// ids, and occurrences carry a components.id surrogate. None of these ever equals another, which is the
// mismatch #819 describes; a join that only works when two of them collide fails these tests.

type fakeProcesses struct {
	byHost map[shared.ID][]ports.ProcessSnapshot
}

func (p fakeProcesses) ListRunningByAsset(_ context.Context, assetID shared.ID) ([]ports.ProcessSnapshot, error) {
	return p.byHost[assetID], nil
}

type fakeComponents struct {
	byEng map[shared.ID][]sbom.ComponentRecord
}

func (c fakeComponents) ListCurrentComponentsByEngagement(_ context.Context, _, engagementID shared.ID) ([]sbom.ComponentRecord, error) {
	return c.byEng[engagementID], nil
}

type fakeMembership struct {
	engs      []*engagement.Engagement
	engErr    error
	projects  []asset.ComponentMembership
	technical []asset.ComponentMembership
}

func (m fakeMembership) ListEngagementsByBusinessAsset(_ context.Context, _, _ shared.ID) ([]*engagement.Engagement, error) {
	return m.engs, m.engErr
}
func (m fakeMembership) ListBusinessAssetProjects(_ context.Context, _, _ shared.ID) ([]asset.ComponentMembership, error) {
	return m.projects, nil
}
func (m fakeMembership) ListBusinessAssetTechnicalAssets(_ context.Context, _, _ shared.ID) ([]asset.ComponentMembership, error) {
	return m.technical, nil
}

// fakeContexts resolves project ids and host asset ids to their hidden engagement contexts.
type fakeContexts struct {
	projects map[shared.ID]*engagement.Engagement
	hosts    map[shared.ID]*engagement.Engagement
	err      error
}

func (c fakeContexts) ProjectContexts(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]*engagement.Engagement, error) {
	if c.err != nil {
		return nil, c.err
	}
	out := map[shared.ID]*engagement.Engagement{}
	for _, id := range ids {
		if e, ok := c.projects[id]; ok {
			out[id] = e
		}
	}
	return out, nil
}

func (c fakeContexts) GetByHostAssetID(_ context.Context, _, assetID shared.ID) (*engagement.Engagement, error) {
	if c.err != nil {
		return nil, c.err
	}
	if e, ok := c.hosts[assetID]; ok {
		return e, nil
	}
	return nil, shared.ErrNotFound
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

func projectMember(projectID string) asset.ComponentMembership {
	return asset.ComponentMembership{TenantID: "t1", AssetID: "asset-1", ComponentID: shared.ID(projectID), Role: asset.MembershipRole("dependency")}
}

func techHost(host string) asset.ComponentMembership {
	return asset.ComponentMembership{TenantID: "t1", AssetID: "asset-1", ComponentID: shared.ID(host), Role: asset.MembershipRole("technical")}
}

func occ(id, eng, comp, adv string) vulnerabilityoccurrence.Occurrence {
	return vulnerabilityoccurrence.Occurrence{TenantID: "t1", ID: shared.ID(id), EngagementID: shared.ID(eng), AdvisoryID: adv, ComponentID: shared.ID(comp), State: vulnerabilityoccurrence.StateDetected}
}

func assess(pri int, kev bool) vulnerabilityrisk.Assessment {
	return vulnerabilityrisk.Assessment{Priority: pri, KEV: kev, Severity: shared.SeverityHigh}
}

func mustReader(t *testing.T, m MembershipReader, c ContextResolver, o OccurrenceReader, r RiskReader) *Reader {
	t.Helper()
	rd, err := NewReader(m, c, o, r)
	if err != nil {
		t.Fatalf("new reader: %v", err)
	}
	return rd
}

func oneEngagement() []*engagement.Engagement { return []*engagement.Engagement{{ID: "eng-1"}} }

var (
	projectCtx = &engagement.Engagement{ID: "ctx-proj-1", ProjectID: "proj-1"}
	hostCtx    = &engagement.Engagement{ID: "ctx-host-1", HostAssetID: "host-1"}
	contexts   = fakeContexts{projects: map[shared.ID]*engagement.Engagement{"proj-1": projectCtx}, hosts: map[shared.ID]*engagement.Engagement{"host-1": hostCtx}}
)

func TestAbstainNoEngagementsAndNoMemberships(t *testing.T) {
	rd := mustReader(t, fakeMembership{}, contexts, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("no engagements must abstain with ErrNotFound, got %v", err)
	}
}

// A linked project that was never analysed and a linked host that never reported packages have no
// context; with nothing else the asset has no exposure data and must abstain, not read as clean.
func TestAbstainWhenLinkedComponentsHaveNoContextYet(t *testing.T) {
	m := fakeMembership{projects: []asset.ComponentMembership{projectMember("proj-new")}, technical: []asset.ComponentMembership{techHost("host-new")}}
	rd := mustReader(t, m, contexts, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unresolved contexts must abstain with ErrNotFound, got %v", err)
	}
}

// With a component lister wired, an engagement set that has no component inventory anywhere was never
// scanned: abstain rather than report a clean.
func TestAbstainWhenNothingWasScanned(t *testing.T) {
	m := fakeMembership{engs: oneEngagement()}
	rd, err := NewReaderWithRuntime(m, contexts, &fakeOccurrences{}, fakeRisk{}, fakeProcesses{}, fakeComponents{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("no inventory must abstain with ErrNotFound, got %v", err)
	}
}

func TestScannedCleanReturnsEmpty(t *testing.T) {
	m := fakeMembership{engs: oneEngagement()}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{}} // no open occurrences
	rd := mustReader(t, m, contexts, occs, fakeRisk{})
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

// The join #819 describes: a project membership (project id) and a host membership (fleet asset id) reach
// their occurrences through the hidden contexts, alongside the assigned engagement. Component ids are
// SBOM surrogates that equal none of the membership ids.
func TestJoinResolvesProjectAndHostContexts(t *testing.T) {
	m := fakeMembership{
		engs:      oneEngagement(),
		projects:  []asset.ComponentMembership{projectMember("proj-1")},
		technical: []asset.ComponentMembership{techHost("host-1")},
	}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{
		"eng-1":      {occ("o1", "eng-1", "comp-a", "CVE-1")},
		"ctx-proj-1": {occ("o2", "ctx-proj-1", "comp-b", "CVE-2"), occ("o4", "ctx-proj-1", "comp-b", "CVE-4")}, // o4 unscored -> skipped
		"ctx-host-1": {occ("o3", "ctx-host-1", "comp-c", "CVE-3")},
		"eng-other":  {occ("o9", "eng-other", "comp-z", "CVE-9")}, // not the asset's engagement
	}}
	risk := fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{
		"o1": assess(1, true),
		"o2": assess(3, false),
		"o3": assess(2, false),
		"o9": assess(1, true),
	}}
	rd := mustReader(t, m, contexts, occs, risk)
	got, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 vulnerable components (comp-a, comp-b, comp-c), got %d: %+v", len(got), got)
	}
	if got[0].ComponentID != "comp-a" || got[0].AdvisoryID != "CVE-1" || got[0].Priority != 1 || !got[0].KEV || got[0].Running {
		t.Fatalf("assigned engagement entry wrong: %+v", got[0])
	}
	if got[1].ComponentID != "comp-b" || got[1].AdvisoryID != "CVE-2" || got[1].Priority != 3 {
		t.Fatalf("project context entry wrong: %+v", got[1])
	}
	if got[2].ComponentID != "comp-c" || got[2].AdvisoryID != "CVE-3" || got[2].Priority != 2 {
		t.Fatalf("host context entry wrong: %+v", got[2])
	}
}

// A project linked twice, or a context that is also the assigned engagement, is read once.
func TestEngagementsAreDeduplicated(t *testing.T) {
	m := fakeMembership{
		engs:     []*engagement.Engagement{projectCtx},
		projects: []asset.ComponentMembership{projectMember("proj-1"), projectMember("proj-1")},
	}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{"ctx-proj-1": {occ("o1", "ctx-proj-1", "comp-a", "CVE-1")}}}
	rd := mustReader(t, m, contexts, occs, fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{"o1": assess(2, false)}})
	got, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("duplicate engagement produced %d entries", len(got))
	}
}

func TestDedupKeepsWorstRiskAcrossEngagements(t *testing.T) {
	m := fakeMembership{engs: []*engagement.Engagement{{ID: "eng-1"}, {ID: "eng-2"}}}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{
		"eng-1": {occ("o1", "eng-1", "comp-a", "CVE-1")},
		"eng-2": {occ("o1b", "eng-2", "comp-a", "CVE-1")},
	}}
	// Divergent risk for the same (component, advisory): eng-1 sees a mild P3 non-KEV, eng-2 a P1 KEV.
	// The dedup must keep the WORST (P1 KEV) so the exposure factor is never under-reported.
	risk := fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{
		"o1":  assess(3, false),
		"o1b": assess(1, true),
	}}
	rd := mustReader(t, m, contexts, occs, risk)
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
	m := fakeMembership{engs: oneEngagement()}
	// Detected occurrence, but no risk assessment exists for it yet.
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{"eng-1": {occ("o1", "eng-1", "comp-a", "CVE-1")}}}
	rd := mustReader(t, m, contexts, occs, fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{}})
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("all-unscored detected occurrences must abstain (ErrNotFound), not read as clean, got %v", err)
	}
}

func TestRunningVsInstalledMarksRunning(t *testing.T) {
	m := fakeMembership{
		engs:      oneEngagement(),
		technical: []asset.ComponentMembership{techHost("host-1")}, // the host bridge; host-1 also has a context
	}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{
		"eng-1":      {occ("o1", "eng-1", "comp-a", "CVE-1"), occ("o2", "eng-1", "comp-b", "CVE-2")},
		"ctx-host-1": {occ("o3", "ctx-host-1", "comp-c", "CVE-3")},
	}}
	risk := fakeRisk{byOcc: map[shared.ID]vulnerabilityrisk.Assessment{"o1": assess(2, false), "o2": assess(2, false), "o3": assess(2, false)}}
	// host-1 runs /usr/bin/openssl; comp-a is "openssl" (running), comp-b is "leftpad" (installed-only),
	// comp-c is the host's own openssl package (running).
	procs := fakeProcesses{byHost: map[shared.ID][]ports.ProcessSnapshot{
		"host-1": {{TenantID: "t1", AssetID: "host-1", EntityID: "e1", Path: "/usr/bin/openssl", Comm: "openssl", Running: true, LastSeenAt: time.Unix(1, 0)}},
	}}
	comps := fakeComponents{byEng: map[shared.ID][]sbom.ComponentRecord{
		"eng-1":      {{ComponentID: "comp-a", Name: "openssl"}, {ComponentID: "comp-b", Name: "leftpad"}},
		"ctx-host-1": {{ComponentID: "comp-c", Name: "openssl"}},
	}}
	rd, err := NewReaderWithRuntime(m, contexts, occs, risk, procs, comps)
	if err != nil {
		t.Fatal(err)
	}
	got, err := rd.ListAssetVulnerableComponents(ctxT(), "asset-1")
	if err != nil {
		t.Fatal(err)
	}
	byComp := map[shared.ID]bool{}
	for _, g := range got {
		byComp[g.ComponentID] = g.Running
	}
	if len(byComp) != 3 {
		t.Fatalf("expected 3 components, got %v", byComp)
	}
	if !byComp["comp-a"] || !byComp["comp-c"] {
		t.Fatal("openssl components match a running process and must be Running")
	}
	if byComp["comp-b"] {
		t.Fatal("leftpad has no running process and must be installed-only")
	}
}

func TestRuntimeReaderRequiresBothDeps(t *testing.T) {
	m := fakeMembership{}
	if _, err := NewReaderWithRuntime(m, contexts, &fakeOccurrences{}, fakeRisk{}, nil, fakeComponents{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil process store must be rejected")
	}
	if _, err := NewReaderWithRuntime(m, contexts, &fakeOccurrences{}, fakeRisk{}, fakeProcesses{}, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil component lister must be rejected")
	}
}

func TestValidationAndErrorPropagation(t *testing.T) {
	if _, err := NewReader(nil, contexts, &fakeOccurrences{}, fakeRisk{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil membership rejected")
	}
	if _, err := NewReader(fakeMembership{}, nil, &fakeOccurrences{}, fakeRisk{}); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("nil context resolver rejected")
	}
	rd := mustReader(t, fakeMembership{engs: oneEngagement()}, contexts, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd.ListAssetVulnerableComponents(context.Background(), "asset-1"); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("missing tenant rejected")
	}
	if _, err := rd.ListAssetVulnerableComponents(ctxT(), ""); !errors.Is(err, shared.ErrValidation) {
		t.Fatal("empty asset id rejected")
	}
	boom := errors.New("db down")
	rd2 := mustReader(t, fakeMembership{engs: oneEngagement()}, contexts, &fakeOccurrences{err: boom}, fakeRisk{})
	if _, err := rd2.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, boom) {
		t.Fatalf("occurrence error must propagate, got %v", err)
	}
	occs := &fakeOccurrences{byEng: map[shared.ID][]vulnerabilityoccurrence.Occurrence{"eng-1": {occ("o1", "eng-1", "comp-a", "CVE-1")}}}
	rd3 := mustReader(t, fakeMembership{engs: oneEngagement()}, contexts, occs, fakeRisk{err: boom})
	if _, err := rd3.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, boom) {
		t.Fatalf("risk error must propagate, got %v", err)
	}
	rd4 := mustReader(t, fakeMembership{engErr: boom}, contexts, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd4.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, boom) {
		t.Fatalf("engagement lookup error must propagate, got %v", err)
	}
	rd5 := mustReader(t, fakeMembership{projects: []asset.ComponentMembership{projectMember("proj-1")}}, fakeContexts{err: boom}, &fakeOccurrences{}, fakeRisk{})
	if _, err := rd5.ListAssetVulnerableComponents(ctxT(), "asset-1"); !errors.Is(err, boom) {
		t.Fatalf("context resolution error must propagate, got %v", err)
	}
}
