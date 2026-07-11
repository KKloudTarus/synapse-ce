package audit

import (
	"context"
	"errors"
	"testing"

	auditdom "github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type fakeReader struct {
	report auditdom.Report
	err    error
}

func (f fakeReader) List(context.Context, int) ([]ports.AuditEntry, error) { return nil, nil }
func (f fakeReader) Verify(context.Context) (auditdom.Report, error)       { return f.report, f.err }

// stubSigner returns a sentinel attestation over the head (parity test only – real
// ed25519 correctness is covered in domain/evidence + infrastructure/signing).
type stubSigner struct{ calls int }

func (s *stubSigner) Sign(_ context.Context, head string) (evidence.Attestation, error) {
	s.calls++
	return evidence.Attestation{Algorithm: "ed25519", KeyID: "test", PublicKey: "pk", Head: head, Signature: "sig"}, nil
}
func (s *stubSigner) PublicKey() string { return "pk" }
func (s *stubSigner) KeyID() string     { return "test" }

func TestNewServiceRequiresReader(t *testing.T) {
	if _, err := NewService(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("nil reader must be ErrValidation, got %v", err)
	}
}

func TestVerifyAttestsIntactHead(t *testing.T) {
	signer := &stubSigner{}
	svc, err := NewService(fakeReader{report: auditdom.Report{Intact: true, Verified: 3, Head: "abc"}})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetSigner(signer)
	out, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Attestation == nil || out.Attestation.Head != "abc" || signer.calls != 1 {
		t.Fatalf("intact head must be attested: att=%+v calls=%d", out.Attestation, signer.calls)
	}
}

func TestVerifyDoesNotAttestBrokenOrEmpty(t *testing.T) {
	signer := &stubSigner{}
	// Broken chain → no attestation.
	broken, _ := NewService(fakeReader{report: auditdom.Report{Intact: false, Verified: 2, Head: "x"}})
	broken.SetSigner(signer)
	if out, _ := broken.Verify(context.Background()); out.Attestation != nil {
		t.Error("a broken chain must not be attested")
	}
	// Empty chain (no head) → no attestation.
	empty, _ := NewService(fakeReader{report: auditdom.Report{Intact: true, Head: ""}})
	empty.SetSigner(signer)
	if out, _ := empty.Verify(context.Background()); out.Attestation != nil {
		t.Error("an empty chain must not be attested")
	}
	if signer.calls != 0 {
		t.Errorf("signer must not be called for broken/empty chains, calls=%d", signer.calls)
	}
}

func TestVerifyWithoutSignerIsIntegrityOnly(t *testing.T) {
	svc, _ := NewService(fakeReader{report: auditdom.Report{Intact: true, Verified: 1, Head: "h"}})
	out, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Attestation != nil {
		t.Error("no signer → no attestation, but integrity still reported")
	}
	if !out.Intact || out.Verified != 1 {
		t.Errorf("report must pass through: %+v", out.Report)
	}
}

func TestVerifyPropagatesReaderError(t *testing.T) {
	svc, _ := NewService(fakeReader{err: errors.New("db down")})
	if _, err := svc.Verify(context.Background()); err == nil {
		t.Fatal("reader error must propagate")
	}
}

// ---- external RFC-3161 anchoring of the audit head ----

type stubTSA struct {
	calls int
	fail  bool
}

func (t *stubTSA) Timestamp(_ context.Context, digest []byte) (ports.TimestampToken, error) {
	t.calls++
	if t.fail {
		return ports.TimestampToken{}, errors.New("tsa unreachable")
	}
	return ports.TimestampToken{Authority: "test-tsa", Token: "tok:" + string(digest)}, nil
}

type fakeTSStore struct {
	m    map[string]ports.TimestampToken
	last string
}

func newTSStore() *fakeTSStore { return &fakeTSStore{m: map[string]ports.TimestampToken{}} }
func (f *fakeTSStore) Get(_ context.Context, chain string, eng shared.ID, head string) (*ports.TimestampToken, error) {
	if t, ok := f.m[chain+eng.String()+head]; ok {
		c := t
		return &c, nil
	}
	return nil, nil
}
func (f *fakeTSStore) Put(_ context.Context, chain string, eng shared.ID, head string, tok ports.TimestampToken) error {
	f.m[chain+eng.String()+head] = tok
	f.last = head
	return nil
}
func (f *fakeTSStore) LatestHead(_ context.Context, _ string, _ shared.ID) (string, bool, error) {
	return f.last, f.last != "", nil
}

func TestAuditVerifyAnchorsHead(t *testing.T) {
	svc, _ := NewService(fakeReader{report: auditdom.Report{Intact: true, Verified: 3, Head: "abc"}})
	tsa := &stubTSA{}
	svc.SetTimestamper(tsa, newTSStore())
	out, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.Anchored || out.Timestamp == nil || tsa.calls != 1 {
		t.Fatalf("audit head must be anchored: anchored=%v ts=%v calls=%d", out.Anchored, out.Timestamp, tsa.calls)
	}
}

func TestAuditVerifyPendingWhenTSAUnreachable(t *testing.T) {
	svc, _ := NewService(fakeReader{report: auditdom.Report{Intact: true, Verified: 1, Head: "h"}})
	svc.SetTimestamper(&stubTSA{fail: true}, newTSStore())
	out, err := svc.Verify(context.Background())
	if err != nil {
		t.Fatalf("a failing TSA must not fail the audit verify: %v", err)
	}
	if out.Anchored {
		t.Error("a failing TSA must leave the audit head pending-anchor")
	}
	if !out.Intact {
		t.Error("the report must still report integrity")
	}
}
