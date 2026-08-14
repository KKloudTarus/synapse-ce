package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	evdom "github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	enguc "github.com/KKloudTarus/synapse-ce/internal/usecase/engagement"
	evidenceuc "github.com/KKloudTarus/synapse-ce/internal/usecase/evidence"
)

// in-test evidence store + blob store (adapter tests stay infra-free).
type evStoreFake struct {
	items map[shared.ID][]evdom.Evidence
}

func newEvStoreFake() *evStoreFake { return &evStoreFake{items: map[shared.ID][]evdom.Evidence{}} }
func (s *evStoreFake) Append(_ context.Context, xs []evdom.Evidence) error {
	for _, e := range xs {
		s.items[e.EngagementID] = append(s.items[e.EngagementID], e)
	}
	return nil
}
func (s *evStoreFake) ListByEngagement(_ context.Context, id shared.ID) ([]evdom.Evidence, error) {
	return s.items[id], nil
}
func (s *evStoreFake) Head(_ context.Context, id shared.ID) (string, error) {
	c := s.items[id]
	if len(c) == 0 {
		return "", nil
	}
	return c[len(c)-1].Hash, nil
}

func (s *evStoreFake) LookupSealedForFinding(_ context.Context, engagementID, findingID shared.ID, kind string) (evdom.Evidence, bool, error) {
	chain := s.items[engagementID]
	for i := len(chain) - 1; i >= 0; i-- {
		e := chain[i]
		if e.FindingID == findingID && e.Kind == kind {
			return e, true, nil
		}
	}
	return evdom.Evidence{}, false, nil
}

type blobFake struct{ m map[string][]byte }

func newBlobFake() *blobFake                                        { return &blobFake{m: map[string][]byte{}} }
func (b *blobFake) Put(_ context.Context, k string, d []byte) error { b.m[k] = d; return nil }
func (b *blobFake) Get(_ context.Context, k string) ([]byte, error) {
	d, ok := b.m[k]
	if !ok {
		return nil, shared.ErrNotFound
	}
	return d, nil
}

func newEvidenceRouter(t *testing.T) (*Router, *blobFake) {
	t.Helper()
	repo := newEngRepoFake()
	audit := &fakeAudit{}
	clock := fixedClock{t: time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)}
	engSvc := enguc.NewService(repo, clock, engIDs{}, audit)
	if _, err := engSvc.Create(context.Background(), enguc.CreateInput{Name: "Acme", Client: "Acme"}); err != nil {
		t.Fatalf("seed engagement: %v", err)
	}
	blobs := newBlobFake()
	evSvc, err := evidenceuc.NewService(newEvStoreFake(), blobs, audit, clock, engIDs{})
	if err != nil {
		t.Fatal(err)
	}
	return &Router{log: discardLog(), eng: engSvc, evidence: evSvc}, blobs
}

func TestCaptureEvidenceHandler(t *testing.T) {
	rt, blobs := newEvidenceRouter(t)
	body := `{"kind":"screenshot","filename":"shot.png","note":"login","content_base64":"` +
		base64.StdEncoding.EncodeToString([]byte("screenshot-bytes")) + `"}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/evidence", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.captureEvidence(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("capture: code=%d body=%s", rec.Code, rec.Body.String())
	}
	var link map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &link); err != nil {
		t.Fatal(err)
	}
	ref, _ := link["StorageRef"].(string)
	if ref == "" || blobs.m[ref] == nil {
		t.Fatalf("blob not stored under StorageRef %q", ref)
	}

	// Unknown engagement -> 404. In production this route is wrapped by withEngTenant (the
	// tenant-isolation chokepoint), which is also what 404s an unknown engagement; exercise it
	// through the wrapper since the handler itself no longer repeats the lookup.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/engagements/nope/evidence", strings.NewReader(body))
	req.SetPathValue("id", "nope")
	rec = httptest.NewRecorder()
	rt.withEngTenant(rt.captureEvidence)(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown engagement: want 404, got %d", rec.Code)
	}

	// Invalid base64 -> 400.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/evidence", strings.NewReader(`{"content_base64":"!!!"}`))
	req.SetPathValue("id", "eng-1")
	rec = httptest.NewRecorder()
	rt.captureEvidence(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad base64: want 400, got %d", rec.Code)
	}
}

func TestDownloadArtifactHandler(t *testing.T) {
	rt, blobs := newEvidenceRouter(t)
	data := []byte("screenshot-bytes")
	body := `{"kind":"screenshot","content_base64":"` + base64.StdEncoding.EncodeToString(data) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/engagements/eng-1/evidence", strings.NewReader(body))
	req.SetPathValue("id", "eng-1")
	rec := httptest.NewRecorder()
	rt.captureEvidence(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("capture: %d", rec.Code)
	}
	var link map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &link)
	sha := link["StorageRef"].(string)

	// Download returns the exact bytes.
	dl := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/engagements/eng-1/evidence/"+sha, nil)
		req.SetPathValue("id", "eng-1")
		req.SetPathValue("sha", sha)
		rec := httptest.NewRecorder()
		rt.downloadArtifact(rec, req)
		return rec
	}
	rec = dl()
	if rec.Code != http.StatusOK || rec.Body.String() != string(data) {
		t.Fatalf("download: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// Tamper the stored blob -> integrity check fails with 409.
	blobs.m[sha] = []byte("tampered")
	if rec := dl(); rec.Code != http.StatusConflict {
		t.Errorf("tampered artifact: want 409, got %d", rec.Code)
	}
}
