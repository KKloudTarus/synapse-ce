package fleetupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// --- fakes ---

type fakeDownloader struct {
	data []byte
	err  error
}

func (f fakeDownloader) Download(context.Context, string) ([]byte, error) { return f.data, f.err }

type fakeVerifier struct{ err error }

func (f fakeVerifier) Verify([]byte, []byte) error { return f.err }

type fakeInstaller struct {
	installed    bool
	rolledBack   bool
	installErr   error
	rollbackErr  error
	installedVer string
}

func (f *fakeInstaller) Install(_ context.Context, _ []byte, ver string) error {
	if f.installErr != nil {
		return f.installErr
	}
	f.installed = true
	f.installedVer = ver
	return nil
}
func (f *fakeInstaller) Rollback(context.Context) error {
	if f.rollbackErr != nil {
		return f.rollbackErr
	}
	f.rolledBack = true
	return nil
}

type fakeHealth struct {
	ok  bool
	err error
}

func (f fakeHealth) Healthy(context.Context) (bool, error) { return f.ok, f.err }

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func mustUpdater(t *testing.T, dl Downloader, ver Verifier, inst Installer, h HealthProber) *Updater {
	t.Helper()
	u, err := New(dl, ver, inst, h)
	if err != nil {
		t.Fatalf("new updater: %v", err)
	}
	return u
}

const cur = "1.0.0"

func newPlan(artifact []byte) Plan {
	return Plan{TargetVersion: "1.1.0", URL: "https://cp/artifact", SHA256: sha256hex(artifact), Signature: []byte("sig")}
}

func TestApplySuccessInstallsAndCommits(t *testing.T) {
	art := []byte("new-binary-bytes")
	inst := &fakeInstaller{}
	u := mustUpdater(t, fakeDownloader{data: art}, fakeVerifier{}, inst, fakeHealth{ok: true})
	out, err := u.Apply(context.Background(), cur, newPlan(art))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !out.Applied || out.RolledBack || out.Reason != ReasonHealthy {
		t.Fatalf("expected Applied, got %+v", out)
	}
	if !inst.installed || inst.rolledBack || inst.installedVer != "1.1.0" {
		t.Fatalf("installer state wrong: %+v", inst)
	}
}

func TestApplyChecksumMismatchRefusesWithoutInstalling(t *testing.T) {
	art := []byte("new-binary-bytes")
	p := newPlan(art)
	p.SHA256 = sha256hex([]byte("something-else")) // tampered checksum
	inst := &fakeInstaller{}
	u := mustUpdater(t, fakeDownloader{data: art}, fakeVerifier{}, inst, fakeHealth{ok: true})
	out, err := u.Apply(context.Background(), cur, p)
	if err == nil || out.Reason != ReasonChecksumMismatch {
		t.Fatalf("checksum mismatch must error+refuse, got %+v err=%v", out, err)
	}
	if inst.installed {
		t.Fatal("a checksum mismatch must NOT install — the running version stays untouched")
	}
}

func TestApplySignatureInvalidRefusesWithoutInstalling(t *testing.T) {
	art := []byte("new-binary-bytes")
	inst := &fakeInstaller{}
	u := mustUpdater(t, fakeDownloader{data: art}, fakeVerifier{err: errors.New("bad sig")}, inst, fakeHealth{ok: true})
	out, err := u.Apply(context.Background(), cur, newPlan(art))
	if err == nil || out.Reason != ReasonSignatureInvalid {
		t.Fatalf("bad signature must error+refuse, got %+v err=%v", out, err)
	}
	if inst.installed {
		t.Fatal("a signature failure must NOT install")
	}
}

func TestApplyUnhealthyRollsBack(t *testing.T) {
	art := []byte("new-binary-bytes")
	inst := &fakeInstaller{}
	u := mustUpdater(t, fakeDownloader{data: art}, fakeVerifier{}, inst, fakeHealth{ok: false})
	out, err := u.Apply(context.Background(), cur, newPlan(art))
	if err == nil || !out.RolledBack || out.Applied || out.Reason != ReasonRolledBack {
		t.Fatalf("unhealthy must roll back, got %+v err=%v", out, err)
	}
	if !inst.installed || !inst.rolledBack {
		t.Fatalf("must have installed then rolled back: %+v", inst)
	}
	if out.From != cur || out.To != "1.1.0" {
		t.Fatalf("rollback must report the version pair, got %+v", out)
	}
}

func TestApplyRollbackFailureSurfacesLoudly(t *testing.T) {
	art := []byte("new-binary-bytes")
	inst := &fakeInstaller{rollbackErr: errors.New("disk gone")}
	u := mustUpdater(t, fakeDownloader{data: art}, fakeVerifier{}, inst, fakeHealth{ok: false})
	_, err := u.Apply(context.Background(), cur, newPlan(art))
	if err == nil {
		t.Fatal("a failed rollback after an unhealthy install must surface an error")
	}
}

func TestApplyNotNewerIsNoOp(t *testing.T) {
	art := []byte("x")
	inst := &fakeInstaller{}
	p := newPlan(art)
	p.TargetVersion = "1.0.0" // equal, not newer
	u := mustUpdater(t, fakeDownloader{data: art}, fakeVerifier{}, inst, fakeHealth{ok: true})
	out, err := u.Apply(context.Background(), cur, p)
	if err != nil || out.Attempted || out.Reason != ReasonNotNewer {
		t.Fatalf("equal version must be a no-op, got %+v err=%v", out, err)
	}
	if inst.installed {
		t.Fatal("a not-newer plan must not install (no auto-downgrade)")
	}
}

func TestApplyIncompletePlanIsNoOp(t *testing.T) {
	inst := &fakeInstaller{}
	u := mustUpdater(t, fakeDownloader{data: []byte("x")}, fakeVerifier{}, inst, fakeHealth{ok: true})
	for _, p := range []Plan{
		{TargetVersion: "", URL: "u", SHA256: "s", Signature: []byte("s")},
		{TargetVersion: "1.1.0", URL: "", SHA256: "s", Signature: []byte("s")},
		{TargetVersion: "1.1.0", URL: "u", SHA256: "", Signature: []byte("s")},
		{TargetVersion: "1.1.0", URL: "u", SHA256: "s", Signature: nil},
	} {
		out, err := u.Apply(context.Background(), cur, p)
		if err != nil || out.Attempted || out.Reason != ReasonIncompletePlan {
			t.Fatalf("incomplete plan %+v must be a no-op, got %+v err=%v", p, out, err)
		}
	}
	if inst.installed {
		t.Fatal("an incomplete plan must never install")
	}
}

// End-to-end with the REAL ed25519 verifier: a genuine signature verifies; a tampered artifact does not.
func TestEd25519VerifierRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewEd25519Verifier(hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	art := []byte("release-artifact")
	sig := ed25519.Sign(priv, art)
	if err := v.Verify(art, sig); err != nil {
		t.Fatalf("a genuine signature must verify: %v", err)
	}
	if err := v.Verify([]byte("tampered"), sig); err == nil {
		t.Fatal("a signature over different bytes must NOT verify")
	}
	if err := v.Verify(art, []byte("short")); err == nil {
		t.Fatal("a malformed signature must be rejected")
	}

	// And through the full Apply path: real verifier + matching checksum + healthy → applied.
	inst := &fakeInstaller{}
	u := mustUpdater(t, fakeDownloader{data: art}, v, inst, fakeHealth{ok: true})
	p := Plan{TargetVersion: "1.1.0", URL: "https://cp/a", SHA256: sha256hex(art), Signature: sig}
	out, err := u.Apply(context.Background(), cur, p)
	if err != nil || !out.Applied {
		t.Fatalf("real-verifier happy path must apply, got %+v err=%v", out, err)
	}
}

func TestNewRequiresAllSeams(t *testing.T) {
	if _, err := New(nil, fakeVerifier{}, &fakeInstaller{}, fakeHealth{}); err == nil {
		t.Fatal("nil downloader must be rejected")
	}
}
