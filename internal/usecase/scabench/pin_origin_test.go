package scabench

import (
	"os"
	"strings"
	"testing"
)

// loadCommittedCatalog decodes the shipped benchmark catalog through the production decoder, so this
// test exercises the same validation path the runner uses.
func loadCommittedCatalog(t *testing.T) Catalog {
	t.Helper()
	file, err := os.Open("corpus/catalog.json")
	if err != nil {
		t.Fatalf("open committed catalog: %v", err)
	}
	defer func() { _ = file.Close() }()
	catalog, err := DecodeCatalog(file)
	if err != nil {
		t.Fatalf("decode committed catalog: %v", err)
	}
	return catalog
}

// pinnedCatalog returns a valid catalog carrying exactly the supplied pins.
func pinnedCatalog(pins ...ArtifactPin) Catalog {
	catalog := validCatalog()
	catalog.Pins = pins
	return catalog
}

func databasePin(origin string) ArtifactPin {
	return ArtifactPin{
		Reference: "database:grype:v6.1.9-2026-09-20T00:35:35Z-1789885674",
		Digest:    "sha256:" + hexDigest('c'),
		Origin:    origin,
	}
}

// TestCatalogRequiresOriginForRotatingArtifactKinds pins the reason this field exists. A digest proves
// two captures used the same bytes but does not say where those bytes came from, and advisory
// databases are routinely republished in place, so a digest-only pin can silently become
// unobtainable. Databases and authoritative source documents must therefore name an origin.
func TestCatalogRequiresOriginForRotatingArtifactKinds(t *testing.T) {
	for _, reference := range []string{
		"database:grype:v6.1.9-2026-09-20T00:35:35Z-1789885674",
		"database:owned:sles-15-sp6-affected-oval-2026-09-20",
		"source:sles-15-sp6-affected-oval-2026-09-20",
	} {
		t.Run(reference, func(t *testing.T) {
			catalog := pinnedCatalog(ArtifactPin{Reference: reference, Digest: "sha256:" + hexDigest('c')})
			err := catalog.Validate()
			if err == nil {
				t.Fatal("a rotating artifact pin without an origin must be rejected")
			}
			if !strings.Contains(err.Error(), "requires an origin") {
				t.Fatalf("error must name the missing origin, got %v", err)
			}
		})
	}
}

// TestCatalogAllowsOriginlessLocalArtifactKinds keeps the requirement narrow. A locally built runner,
// an environment descriptor, a profile, and a tool config have no upstream download to record, so
// demanding an origin for them would force a fabricated URL.
func TestCatalogAllowsOriginlessLocalArtifactKinds(t *testing.T) {
	for _, reference := range []string{
		"binary:synapse-sca-bench:reproducible-v1",
		"environment:al2023-amd64-trusted-sandbox-v1",
		"environment-attestation:al2023-amd64-trusted-sandbox-v1",
		"profile:grype:offline-sbom-v1",
		"syft-config:offline-docker-v1",
	} {
		t.Run(reference, func(t *testing.T) {
			catalog := pinnedCatalog(ArtifactPin{Reference: reference, Digest: "sha256:" + hexDigest('c')})
			if err := catalog.Validate(); err != nil {
				t.Fatalf("a locally produced artifact must remain pinnable by digest alone: %v", err)
			}
		})
	}
}

// TestCatalogRejectsUnsafePinOrigin covers the forms that would make an origin misleading or unsafe.
// A committed pin is public, so a credential-bearing origin would both leak a secret into history and
// be unusable by anyone else; a plaintext or relative origin cannot be transport-authenticated.
func TestCatalogRejectsUnsafePinOrigin(t *testing.T) {
	for _, current := range []struct {
		name   string
		origin string
	}{
		{name: "plaintext http", origin: "http://grype.anchore.io/databases/v6/db.tar.zst"},
		{name: "credential in userinfo", origin: "https://user:token@grype.anchore.io/db.tar.zst"},
		{name: "bare userinfo", origin: "https://token@grype.anchore.io/db.tar.zst"},
		{name: "relative path", origin: "/databases/v6/db.tar.zst"},
		{name: "scheme only", origin: "https://"},
		{name: "opaque", origin: "https:db.tar.zst"},
		{name: "fragment", origin: "https://grype.anchore.io/db.tar.zst#part"},
		{name: "file scheme", origin: "file:///var/lib/db.tar.zst"},
		{name: "leading whitespace", origin: " https://grype.anchore.io/db.tar.zst"},
		{name: "oci without repository", origin: "oci://ghcr.io"},
	} {
		t.Run(current.name, func(t *testing.T) {
			if err := pinnedCatalog(databasePin(current.origin)).Validate(); err == nil {
				t.Fatalf("origin %q must be rejected", current.origin)
			}
		})
	}
}

// TestCatalogAcceptsAuthenticatedPinOrigin admits the two shapes vendors actually publish: an https
// URL for feeds and release archives, and a registry reference for a database distributed only as an
// OCI artifact, which is how the trivy database ships.
func TestCatalogAcceptsAuthenticatedPinOrigin(t *testing.T) {
	for _, origin := range []string{
		"https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.9_2026-09-20T00:35:35Z_1789885674.tar.zst",
		"https://ftp.suse.com/pub/projects/security/oval/suse.linux.enterprise.15-sp6-affected.xml.gz",
		"https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip",
		"oci://ghcr.io/aquasecurity/trivy-db:2",
	} {
		t.Run(origin, func(t *testing.T) {
			if err := pinnedCatalog(databasePin(origin)).Validate(); err != nil {
				t.Fatalf("authoritative origin %q must be accepted: %v", origin, err)
			}
		})
	}
}

// TestCatalogStillRequiresImmutableDigest guards against the origin field being read as a substitute
// for the digest. Origin says where to look; only the digest says the bytes are the right ones.
func TestCatalogStillRequiresImmutableDigest(t *testing.T) {
	pin := databasePin("https://grype.anchore.io/databases/v6/db.tar.zst")
	pin.Digest = ""
	if err := pinnedCatalog(pin).Validate(); err == nil {
		t.Fatal("an origin must not substitute for an immutable digest")
	}
	pin.Digest = "sha256:not-a-digest"
	if err := pinnedCatalog(pin).Validate(); err == nil {
		t.Fatal("a malformed digest must be rejected even when an origin is present")
	}
}

// TestCommittedCatalogPinsCarryOriginForRotatingKinds asserts the shipped corpus satisfies the
// invariant, so the benchmark's own pin set stays re-obtainable rather than only the synthetic
// fixtures above.
func TestCommittedCatalogPinsCarryOriginForRotatingKinds(t *testing.T) {
	catalog := loadCommittedCatalog(t)
	if len(catalog.Pins) == 0 {
		t.Fatal("committed catalog must carry artifact pins")
	}
	rotating := 0
	for _, pin := range catalog.Pins {
		if !originRequiredPinKind(pin.Reference) {
			continue
		}
		rotating++
		if strings.TrimSpace(pin.Origin) == "" {
			t.Errorf("committed pin %q must carry an origin", pin.Reference)
		}
	}
	if rotating == 0 {
		t.Fatal("committed catalog must pin at least one database or source artifact")
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("committed catalog must satisfy its own pin invariants: %v", err)
	}
}
