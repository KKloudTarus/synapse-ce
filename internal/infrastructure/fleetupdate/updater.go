// Package fleetupdate is the agent self-update state machine (#412, epic #405): download a
// control-plane-offered version, VERIFY its checksum and signature BEFORE replacing anything, install
// atomically, then gate on a successful health check and AUTOMATICALLY ROLL BACK if the new version
// does not become healthy within a bounded window.
//
// The orchestration here is pure and fully unit-tested; the fallible/side-effecting steps (download
// over the mTLS channel, atomic binary swap + service-manager restart) are injected as seams so the
// verify-then-swap-then-health-gate contract can be exercised without touching a real host. A tampered
// checksum or signature is refused with NOTHING installed; a health-check failure restores the prior
// version and reports the version pair.
package fleetupdate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetversion"
)

// Plan is an update the control plane offered (carried on the heartbeat response). Every field is
// required for an update to proceed; a missing field fails closed (no update).
//
// SECURITY NOTE for whoever wires the real Downloader/Installer: Signature here is verified over the
// artifact BYTES. TargetVersion and SHA256 are otherwise unauthenticated labels used for the
// not-newer guard. To close a downgrade-via-relabel gap (pairing a validly-signed OLDER artifact with
// a higher TargetVersion), the release pipeline should sign a manifest that BINDS {version, sha256,
// url} and the Verifier should check that manifest, not just the raw bytes.
type Plan struct {
	TargetVersion string // e.g. "1.4.0"
	URL           string // authenticated download location
	SHA256        string // expected artifact checksum, lowercase hex
	Signature     []byte // detached signature over the artifact bytes (see SECURITY NOTE)
}

// Downloader fetches the artifact bytes for a plan over the authenticated channel.
type Downloader interface {
	Download(ctx context.Context, url string) ([]byte, error)
}

// Verifier verifies a detached signature over the artifact bytes with the project's release key.
type Verifier interface {
	Verify(artifact, signature []byte) error
}

// Installer performs the atomic swap of the running binary (keeping a backup) and restarts under the
// service manager, and can restore the previous version on rollback.
type Installer interface {
	Install(ctx context.Context, artifact []byte, targetVersion string) error
	Rollback(ctx context.Context) error
}

// HealthProber reports whether the freshly-installed version has reported a successful heartbeat
// within the rollback window.
type HealthProber interface {
	Healthy(ctx context.Context) (bool, error)
}

// Updater orchestrates a single update attempt.
type Updater struct {
	dl     Downloader
	ver    Verifier
	inst   Installer
	health HealthProber
}

// New constructs an Updater. All seams are required.
func New(dl Downloader, ver Verifier, inst Installer, health HealthProber) (*Updater, error) {
	if dl == nil || ver == nil || inst == nil || health == nil {
		return nil, errors.New("fleetupdate: downloader, verifier, installer and health prober are all required")
	}
	return &Updater{dl: dl, ver: ver, inst: inst, health: health}, nil
}

// Outcome describes what an Apply did. Exactly one of Applied/RolledBack is true when err is nil and
// an update was attempted; both are false when the plan was a no-op (not newer / incomplete).
type Outcome struct {
	Attempted  bool   // a valid, newer plan was acted on
	Applied    bool   // the new version installed AND became healthy
	RolledBack bool   // installed but unhealthy → previous version restored
	From       string // current version before the attempt
	To         string // plan target version
	Reason     string // machine-readable reason
}

// Reasons.
const (
	ReasonNotNewer         = "target_not_newer"
	ReasonIncompletePlan   = "incomplete_plan"
	ReasonDownloadFailed   = "download_failed"
	ReasonChecksumMismatch = "checksum_mismatch"
	ReasonSignatureInvalid = "signature_invalid"
	ReasonInstallFailed    = "install_failed"
	ReasonHealthy          = "healthy"
	ReasonRolledBack       = "health_check_failed_rolled_back"
)

// Apply runs one update attempt from currentVersion toward the plan. Verification happens BEFORE any
// swap: a checksum or signature failure returns an error with nothing installed (the running version
// is untouched). After a successful install, an unhealthy new version is rolled back automatically.
func (u *Updater) Apply(ctx context.Context, currentVersion string, p Plan) (Outcome, error) {
	out := Outcome{From: currentVersion, To: p.TargetVersion}

	// Incomplete plan → no-op (fail closed: never install without a checksum + signature + source).
	if strings.TrimSpace(p.TargetVersion) == "" || strings.TrimSpace(p.URL) == "" ||
		strings.TrimSpace(p.SHA256) == "" || len(p.Signature) == 0 {
		out.Reason = ReasonIncompletePlan
		return out, nil
	}
	// Only move forward, fail-closed: install ONLY when both versions parse and the target is strictly
	// newer. An unparseable target OR an unparseable current version is a no-op — we never install when
	// we cannot prove the target is newer, so this can neither auto-downgrade nor install blindly.
	cur, curOK := fleetversion.Parse(currentVersion)
	tgt, tgtOK := fleetversion.Parse(p.TargetVersion)
	if !tgtOK || !curOK || !cur.Less(tgt) {
		out.Reason = ReasonNotNewer
		return out, nil
	}

	out.Attempted = true

	artifact, err := u.dl.Download(ctx, p.URL)
	if err != nil {
		out.Reason = ReasonDownloadFailed
		return out, fmt.Errorf("fleetupdate: download: %w", err)
	}
	// Verify checksum THEN signature, both before touching the installed binary.
	if !checksumMatches(artifact, p.SHA256) {
		out.Reason = ReasonChecksumMismatch
		return out, fmt.Errorf("fleetupdate: %s", ReasonChecksumMismatch)
	}
	if err := u.ver.Verify(artifact, p.Signature); err != nil {
		out.Reason = ReasonSignatureInvalid
		return out, fmt.Errorf("fleetupdate: %s: %w", ReasonSignatureInvalid, err)
	}

	// Verified — install atomically (the Installer keeps a backup for rollback).
	if err := u.inst.Install(ctx, artifact, p.TargetVersion); err != nil {
		out.Reason = ReasonInstallFailed
		return out, fmt.Errorf("fleetupdate: install: %w", err)
	}

	// Health-gate the new version; roll back on failure.
	healthy, herr := u.health.Healthy(ctx)
	if herr != nil || !healthy {
		if rbErr := u.inst.Rollback(ctx); rbErr != nil {
			// Rollback itself failed — the host may be in a bad state; surface loudly.
			return out, fmt.Errorf("fleetupdate: new version %s unhealthy AND rollback failed: %w (health err: %v)", p.TargetVersion, rbErr, herr)
		}
		out.RolledBack = true
		out.Reason = ReasonRolledBack
		return out, fmt.Errorf("fleetupdate: new version %s failed health check, rolled back to %s", p.TargetVersion, currentVersion)
	}

	out.Applied = true
	out.Reason = ReasonHealthy
	return out, nil
}

// checksumMatches compares sha256(artifact) against the expected lowercase-hex digest in constant time.
func checksumMatches(artifact []byte, expectedHex string) bool {
	sum := sha256.Sum256(artifact)
	got := hex.EncodeToString(sum[:])
	want := strings.ToLower(strings.TrimSpace(expectedHex))
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
