package sca

import (
	"context"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/domain/vulnerability"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// fakeNamedSource is a detection source that only reports a name (Grype / OSV in these tests).
type fakeNamedSource struct{ name string }

func (f fakeNamedSource) Name() string { return f.name }
func (fakeNamedSource) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return nil, nil
}

// fakeCoverageSource is the owned advisory-store source: it reports the ecosystems it covers.
type fakeCoverageSource struct {
	covered map[string]bool
	ok      bool
}

func (fakeCoverageSource) Name() string { return "advisory-store" }
func (fakeCoverageSource) Scan(context.Context, *sbom.SBOM) ([]vulnerability.RawFinding, error) {
	return nil, nil
}
func (f fakeCoverageSource) CoveredEcosystems(context.Context) (map[string]bool, bool, error) {
	return f.covered, f.ok, nil
}

// osDoc is a fixture SBOM with a covered RHEL 9 package and an uncovered Alpine package.
func osDoc() *sbom.SBOM {
	return &sbom.SBOM{Components: []sbom.Component{
		{Name: "openssl", Version: "3.0.7-6.el9", PURL: "pkg:rpm/redhat/openssl@3.0.7-6.el9?distro=rhel-9"}, // Red Hat:9
		{Name: "musl", Version: "1.2.4-r2", PURL: "pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.19"},        // Alpine:v3.19
		{Name: "left-pad", Version: "1.0.0", PURL: "pkg:npm/left-pad@1.0.0"},                                // language pkg: not an OS distro
	}}
}

// TestOSDistroCoverageReadiness pins the owned-only OS-distro coverage guard (EPIC #1034, #1037):
// it flags an OS distro the owned store does not cover ONLY when Grype is absent, names only the uncovered
// distro, and is a no-op when Grype is present, when the store covers every OS distro, or when no source can
// report coverage.
func TestOSDistroCoverageReadiness(t *testing.T) {
	ctx := context.Background()
	owned := fakeCoverageSource{covered: map[string]bool{"Red Hat:9": true}, ok: true} // covers RHEL 9, not Alpine
	grype := fakeNamedSource{name: "grype"}
	osv := fakeNamedSource{name: "osv"}

	t.Run("grype present is a no-op", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{grype, owned}}
		w, incomplete, err := s.osDistroCoverageReadiness(ctx, osDoc())
		if err != nil || incomplete || w != "" {
			t.Fatalf("grype present must be a no-op, got warn=%q incomplete=%v err=%v", w, incomplete, err)
		}
	})

	t.Run("grype absent flags the uncovered distro only", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{osv, owned}}
		w, incomplete, err := s.osDistroCoverageReadiness(ctx, osDoc())
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !incomplete || w == "" {
			t.Fatalf("an uncovered distro with no grype must flag not-confident, got warn=%q incomplete=%v", w, incomplete)
		}
		if !strings.Contains(w, "Alpine:v3.19") {
			t.Errorf("warning must name the uncovered distro Alpine:v3.19, got %q", w)
		}
		// Red Hat:9 is covered (patched CVEs), so it is NOT an uncovered gap, but its OVAL feed is patched-only,
		// so the not-yet-fixed limitation is disclosed rather than left as a silent clean.
		if !strings.Contains(w, "Red Hat:9") || !strings.Contains(w, "not-yet-fixed") {
			t.Errorf("a covered rpm distro must disclose the not-yet-fixed limitation, got %q", w)
		}
	})

	t.Run("covered rpm distro discloses the not-yet-fixed limitation, apk does not", func(t *testing.T) {
		// Every OS distro is covered for patched CVEs. Red Hat:9 is rpm (OVAL, patched-only) so the not-yet-fixed
		// disclosure fires; Alpine (apk, OSV-fed, carries not-yet-fixed) does not. This is the fix for the SLES
		// false-clean: a covered rpm distro is no longer a silent no-op.
		full := fakeCoverageSource{covered: map[string]bool{"Red Hat:9": true, "Alpine:v3.19": true}, ok: true}
		s := &Service{sources: []ports.DetectionSource{osv, full}}
		w, incomplete, err := s.osDistroCoverageReadiness(ctx, osDoc())
		if err != nil || incomplete {
			t.Fatalf("the not-yet-fixed disclosure is a warning, not a hard gap: got incomplete=%v err=%v", incomplete, err)
		}
		if !strings.Contains(w, "Red Hat:9") || !strings.Contains(w, "not-yet-fixed") {
			t.Errorf("covered rpm distro Red Hat:9 must carry the not-yet-fixed disclosure, got %q", w)
		}
		if strings.Contains(w, "Alpine") {
			t.Errorf("a covered apk distro (OSV-fed, carries not-yet-fixed) must NOT get the rpm not-yet-fixed note, got %q", w)
		}
	})

	t.Run("osv-only (no owned store) flags every OS distro", func(t *testing.T) {
		// OwnedAdvisory off ⇒ default resolves to [osv]; OSV skips OS-distro PURLs, so nothing matched the OS
		// packages. Both distros must be flagged, not a silent clean posture.
		s := &Service{sources: []ports.DetectionSource{osv}}
		w, incomplete, err := s.osDistroCoverageReadiness(ctx, osDoc())
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !incomplete || !strings.Contains(w, "Alpine:v3.19") || !strings.Contains(w, "Red Hat:9") {
			t.Fatalf("osv-only with OS packages must flag every OS distro, got warn=%q incomplete=%v", w, incomplete)
		}
	})

	t.Run("file store (present but cannot report) is a no-op", func(t *testing.T) {
		fileStore := fakeCoverageSource{covered: nil, ok: false} // wired, ran matching, but cannot report coverage
		s := &Service{sources: []ports.DetectionSource{osv, fileStore}}
		w, incomplete, err := s.osDistroCoverageReadiness(ctx, osDoc())
		if err != nil || incomplete || w != "" {
			t.Fatalf("a wired-but-unreportable store must be a no-op (matching ran), got warn=%q incomplete=%v err=%v", w, incomplete, err)
		}
	})

	t.Run("unmapped distro is flagged in owned-only mode", func(t *testing.T) {
		full := fakeCoverageSource{covered: map[string]bool{"Red Hat:9": true, "Alpine:v3.19": true}, ok: true}
		doc := &sbom.SBOM{Components: []sbom.Component{
			{Name: "openssl", Version: "1", PURL: "pkg:rpm/centos/openssl@1?distro=centos-9"}, // CentOS Stream: ecosystem ""
		}}
		s := &Service{sources: []ports.DetectionSource{osv, full}}
		w, incomplete, err := s.osDistroCoverageReadiness(ctx, doc)
		if err != nil || !incomplete || !strings.Contains(w, "centos-9") {
			t.Fatalf("an unmapped distro must be flagged, got warn=%q incomplete=%v err=%v", w, incomplete, err)
		}
	})

	t.Run("no OS packages is a no-op", func(t *testing.T) {
		doc := &sbom.SBOM{Components: []sbom.Component{{Name: "left-pad", Version: "1", PURL: "pkg:npm/left-pad@1"}}}
		s := &Service{sources: []ports.DetectionSource{osv}}
		w, incomplete, err := s.osDistroCoverageReadiness(ctx, doc)
		if err != nil || incomplete || w != "" {
			t.Fatalf("a language-only SBOM must be a no-op, got warn=%q incomplete=%v err=%v", w, incomplete, err)
		}
	})

	t.Run("strict sources returns an error on a gap", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{osv, owned}, strictSources: true}
		_, incomplete, err := s.osDistroCoverageReadiness(ctx, osDoc())
		if err == nil || !incomplete {
			t.Fatalf("strict sources must error on an OS-distro coverage gap, got incomplete=%v err=%v", incomplete, err)
		}
	})

	// detectionReadinessAll must surface the distro guard's verdict, not just the coarse no-usable-DB check:
	// osv reports coverage to the coarse check (opaque source), but the OS-distro guard still flags the gap.
	t.Run("detectionReadinessAll surfaces the distro gap", func(t *testing.T) {
		s := &Service{sources: []ports.DetectionSource{osv, owned}}
		w, incomplete, err := s.detectionReadinessAll(ctx, osDoc())
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !incomplete || !strings.Contains(w, "Alpine:v3.19") {
			t.Fatalf("detectionReadinessAll must carry the OS-distro gap through, got warn=%q incomplete=%v", w, incomplete)
		}
	})
}
