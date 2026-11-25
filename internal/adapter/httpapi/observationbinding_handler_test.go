package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/importedfinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/observationbinding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/observationbindinguc"
)

// recordingBinder captures the decision the handler builds and serves a fixed set of approvals.
type recordingBinder struct {
	got      observationbindinguc.DecideRequest
	decided  observationbinding.Binding
	err      error
	approved map[observationbinding.Identity]observationbinding.Binding
	all      []observationbinding.Binding
}

func (r *recordingBinder) Decide(_ context.Context, req observationbindinguc.DecideRequest) (observationbinding.Binding, error) {
	r.got = req
	return r.decided, r.err
}

func (r *recordingBinder) Current(context.Context, shared.ID, shared.ID) (map[observationbinding.Identity]observationbinding.Binding, error) {
	return r.approved, nil
}

func (r *recordingBinder) List(context.Context, shared.ID, shared.ID) ([]observationbinding.Binding, error) {
	return r.all, nil
}

func bindingRequest(t *testing.T, binder *recordingBinder, body string) *httptest.ResponseRecorder {
	t.Helper()
	rt := &Router{}
	rt.SetObservationBindings(binder)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/imported-findings/obs-1/binding", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	req.SetPathValue("observationId", "obs-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	w := httptest.NewRecorder()
	rt.decideObservationBinding(w, req)
	return w
}

// TestBindingDecisionCarriesTheActorAndTheObservation locks the tenancy and attribution contract: the
// actor comes from the authenticated principal and never from the body, and the raw tenant is forwarded
// so the use case can take the row tenant from the engagement it resolves.
func TestBindingDecisionCarriesTheActorAndTheObservation(t *testing.T) {
	t.Parallel()

	binder := &recordingBinder{decided: observationbinding.Binding{
		ID: "b1", Scope: "semgrep", ExternalIdentity: "fingerprint:abc",
		FindingID: "f1", ObservationID: "obs-1", Version: 1,
		DecidedBy: "alice", Reason: "same issue", DecidedAt: time.Unix(1700000000, 0).UTC(),
	}}
	w := bindingRequest(t, binder, `{"finding_id":"f1","reason":"same issue"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if binder.got.Actor != "alice" {
		t.Fatalf("actor = %q, want the authenticated principal", binder.got.Actor)
	}
	if binder.got.ObservationID != "obs-1" || binder.got.FindingID != "f1" || binder.got.EngagementID != "eng-1" {
		t.Fatalf("decision = %+v, want the path observation and the body finding", binder.got)
	}
	if binder.got.ExpectedVersion != 0 {
		t.Fatalf("expected version = %d, want 0 for a first adoption", binder.got.ExpectedVersion)
	}

	var payload bindingPayload
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.Current || payload.Version != 1 || payload.Reason == "" || payload.DecidedBy == "" {
		t.Fatalf("payload = %+v, want a current version carrying its actor and reason", payload)
	}
}

// TestBindingDecisionForwardsTheExpectedVersion keeps the stale-view guard reachable from HTTP: a change
// names the version it is replacing, and a request that omits it is a first adoption, not a silent
// overwrite.
func TestBindingDecisionForwardsTheExpectedVersion(t *testing.T) {
	t.Parallel()

	binder := &recordingBinder{decided: observationbinding.Binding{
		ID: "b2", Scope: "semgrep", ExternalIdentity: "fingerprint:abc", FindingID: "f2",
		ObservationID: "obs-1", Version: 2, DecidedBy: "alice", Reason: "coincidence of line",
		DecidedAt: time.Unix(1700000000, 0).UTC(),
	}}
	if w := bindingRequest(t, binder, `{"finding_id":"f2","reason":"coincidence of line","expected_version":1}`); w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body.String())
	}
	if binder.got.ExpectedVersion != 1 {
		t.Fatalf("expected version = %d, want the version being replaced", binder.got.ExpectedVersion)
	}
}

func TestBindingDecisionRejectsAMalformedBody(t *testing.T) {
	t.Parallel()
	if w := bindingRequest(t, &recordingBinder{}, `not json`); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

// TestImportedFindingReadDistinguishesApprovedFromCandidate is the behaviour #1184 exists for. A
// deduplicator match on file and line is evidence; it is reported as a candidate until a person has
// adopted it, and only then does the read carry an approved finding.
func TestImportedFindingReadDistinguishesApprovedFromCandidate(t *testing.T) {
	t.Parallel()

	at := time.Unix(1700000000, 0).UTC()
	matched := importedfinding.ImportedFinding{
		ID: "obs-approved", TenantID: "t1", EngagementID: "eng-1", FindingID: "f1",
		Severity: shared.SeverityHigh, Title: "approved", Message: "m", Fingerprint: "abc",
		Location:   importedfinding.Location{Path: "src/a.go", StartLine: 1},
		Provenance: importedfinding.Provenance{ToolName: "semgrep", ToolVersion: "1", RuleID: "rule.a", SourceDigest: "d", IngestedBy: "alice", IngestedAt: at},
	}
	candidate := importedfinding.ImportedFinding{
		ID: "obs-candidate", TenantID: "t1", EngagementID: "eng-1", FindingID: "f2",
		Severity: shared.SeverityHigh, Title: "candidate", Message: "m", Fingerprint: "def",
		Location:   importedfinding.Location{Path: "src/b.go", StartLine: 2},
		Provenance: importedfinding.Provenance{ToolName: "semgrep", ToolVersion: "1", RuleID: "rule.b", SourceDigest: "d", IngestedBy: "alice", IngestedAt: at},
	}
	unlinked := importedfinding.ImportedFinding{
		ID: "obs-unlinked", TenantID: "t1", EngagementID: "eng-1",
		Severity: shared.SeverityHigh, Title: "unlinked", Message: "m", Fingerprint: "ghi",
		Location:   importedfinding.Location{Path: "src/c.go", StartLine: 3},
		Provenance: importedfinding.Provenance{ToolName: "semgrep", ToolVersion: "1", RuleID: "rule.c", SourceDigest: "d", IngestedBy: "alice", IngestedAt: at},
	}

	rt := &Router{}
	rt.SetImportedFindings(&fakeImportedFindings{list: []importedfinding.ImportedFinding{matched, candidate, unlinked}})
	rt.SetObservationBindings(&recordingBinder{approved: map[observationbinding.Identity]observationbinding.Binding{
		{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"}: {FindingID: "f1", Version: 3},
	}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/imported-findings", nil)
	req.SetPathValue("id", "eng-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	w := httptest.NewRecorder()
	rt.listImportedFindings(w, req)

	var out []importedFindingPayload
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("%d rows, want 3", len(out))
	}
	states := map[string]importedFindingPayload{}
	for _, row := range out {
		states[row.ID] = row
	}
	if got := states["obs-approved"]; got.Binding != bindingApproved || got.ApprovedFindingID != "f1" || got.BindingVersion != 3 {
		t.Fatalf("adopted row = %+v, want approved on f1 at version 3", got)
	}
	// A location match with no decision behind it must NOT read as approved, and must not carry an
	// approved finding id a caller could act on.
	if got := states["obs-candidate"]; got.Binding != bindingCandidate || got.ApprovedFindingID != "" {
		t.Fatalf("unadopted match = %+v, want candidate with no approved finding", got)
	}
	if got := states["obs-unlinked"]; got.Binding != bindingNone {
		t.Fatalf("unlinked row = %+v, want none", got)
	}
	// finding_id stays on the row for compatibility, which is exactly why the binding field has to exist.
	if states["obs-candidate"].FindingID != "f2" {
		t.Fatalf("finding_id was dropped from a candidate row: %+v", states["obs-candidate"])
	}
}

// TestImportedFindingReadWithoutTheBinderReportsCandidates keeps the unwired deployment honest: with no
// decision record there are no approvals, so nothing may claim one.
func TestImportedFindingReadWithoutTheBinderReportsCandidates(t *testing.T) {
	t.Parallel()

	at := time.Unix(1700000000, 0).UTC()
	rt := &Router{}
	rt.SetImportedFindings(&fakeImportedFindings{list: []importedfinding.ImportedFinding{{
		ID: "obs-1", TenantID: "t1", EngagementID: "eng-1", FindingID: "f1",
		Severity: shared.SeverityHigh, Title: "t", Message: "m", Fingerprint: "abc",
		Provenance: importedfinding.Provenance{ToolName: "semgrep", ToolVersion: "1", RuleID: "r", SourceDigest: "d", IngestedBy: "alice", IngestedAt: at},
	}}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/imported-findings", nil)
	req.SetPathValue("id", "eng-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	w := httptest.NewRecorder()
	rt.listImportedFindings(w, req)

	var out []importedFindingPayload
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0].Binding != bindingCandidate {
		t.Fatalf("rows = %+v, want one candidate", out)
	}
}

// TestAnInheritedApprovalNamesTheRowItWasDecidedOn keeps an approval from looking like it was made on
// this row when it was made on another. A binding is keyed on an identity that outlives the row, so a
// re-imported report inherits the decision; a reader who cannot see which row carried it has no way to
// check what the decider was looking at.
func TestAnInheritedApprovalNamesTheRowItWasDecidedOn(t *testing.T) {
	t.Parallel()

	at := time.Unix(1700000000, 0).UTC()
	reimported := importedfinding.ImportedFinding{
		ID: "obs-tuesday", TenantID: "t1", EngagementID: "eng-1", FindingID: "f1",
		Severity: shared.SeverityHigh, Title: "t", Message: "m", Fingerprint: "abc",
		Provenance: importedfinding.Provenance{ToolName: "semgrep", ToolVersion: "1", RuleID: "r", SourceDigest: "tuesday", IngestedBy: "alice", IngestedAt: at},
	}
	rt := &Router{}
	rt.SetImportedFindings(&fakeImportedFindings{list: []importedfinding.ImportedFinding{reimported}})
	rt.SetObservationBindings(&recordingBinder{approved: map[observationbinding.Identity]observationbinding.Binding{
		{Scope: "semgrep", ExternalIdentity: "fingerprint:abc"}: {FindingID: "f1", Version: 1, ObservationID: "obs-monday"},
	}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/imported-findings", nil)
	req.SetPathValue("id", "eng-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	w := httptest.NewRecorder()
	rt.listImportedFindings(w, req)

	var out []importedFindingPayload
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0].Binding != bindingApproved {
		t.Fatalf("rows = %+v, want the re-imported row to inherit the approval", out)
	}
	if out[0].ApprovedObservationID != "obs-monday" {
		t.Fatalf("approved_observation_id = %q, want the row the decision was made on", out[0].ApprovedObservationID)
	}
}

// TestADanglingBindingIsMarkedOrphaned surfaces a decision that has quietly stopped applying. A tool that
// changes how it fingerprints a result mints a new identity, and the old binding then governs nothing.
// Without this marker the lineage reads as if the observation were still bound.
func TestADanglingBindingIsMarkedOrphaned(t *testing.T) {
	t.Parallel()

	at := time.Unix(1700000000, 0).UTC()
	live := importedfinding.ImportedFinding{
		ID: "obs-live", TenantID: "t1", EngagementID: "eng-1",
		Severity: shared.SeverityHigh, Title: "t", Message: "m", Fingerprint: "new-style",
		Provenance: importedfinding.Provenance{ToolName: "semgrep", ToolVersion: "2", RuleID: "r", SourceDigest: "d", IngestedBy: "alice", IngestedAt: at},
	}
	rt := &Router{}
	rt.SetImportedFindings(&fakeImportedFindings{list: []importedfinding.ImportedFinding{live}})
	rt.SetObservationBindings(&recordingBinder{all: []observationbinding.Binding{
		{ID: "b-stale", Scope: "semgrep", ExternalIdentity: "fingerprint:old-style", FindingID: "f1", ObservationID: "obs-gone", Version: 1, DecidedBy: "alice", Reason: "r", DecidedAt: at},
		{ID: "b-live", Scope: "semgrep", ExternalIdentity: "fingerprint:new-style", FindingID: "f1", ObservationID: "obs-live", Version: 1, DecidedBy: "alice", Reason: "r", DecidedAt: at},
	}})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/observation-bindings", nil)
	req.SetPathValue("id", "eng-1")
	req = req.WithContext(context.WithValue(req.Context(), principalKey, Principal{ID: "alice", Role: "consultant"}))
	w := httptest.NewRecorder()
	rt.listObservationBindings(w, req)

	var out []bindingPayload
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]bindingPayload{}
	for _, row := range out {
		got[row.ID] = row
	}
	if !got["b-stale"].Orphaned {
		t.Fatalf("a binding matching no observation was not marked orphaned: %+v", got["b-stale"])
	}
	if got["b-live"].Orphaned {
		t.Fatalf("a binding that still matches an observation was marked orphaned: %+v", got["b-live"])
	}
}
