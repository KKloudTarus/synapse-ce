package ospkg

import (
	"context"
	"crypto/rsa"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/advisory"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownadvisory"
	"github.com/ProtonMail/go-crypto/openpgp"
)

type centOS7AdvisoryStore struct{}

func (centOS7AdvisoryStore) ByPackage(_ context.Context, ecosystem, name string) ([]advisory.Advisory, error) {
	if ecosystem != "Red Hat:7" || name != "bash" {
		return nil, nil
	}
	return []advisory.Advisory{{
		ID: "CVE-2026-1037",
		Affected: []advisory.AffectedPackage{{
			Ecosystem: "Red Hat:7", Package: "bash",
			Ranges: []advisory.Range{{Type: "ECOSYSTEM", Events: []advisory.Event{
				{Introduced: "0:4.2.46-1.el7"}, {Fixed: "0:4.2.46-35.el7"},
			}}},
		}},
	}}, nil
}

func readCentOSHeader(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCentOS7SignedHeaderAcceptsOnlyPinnedSignerAndImmutableIdentity(t *testing.T) {
	bash := readCentOSHeader(t, "centos7-bash-header.bin")
	name, version, arch, ok := centOS7SignedIdentity(bash)
	if !ok || name != "bash" || version != "4.2.46-34.el7" || arch != "x86_64" {
		t.Fatalf("signed CentOS bash identity=%q %q %q ok=%v", name, version, arch, ok)
	}
	if _, _, _, ok := centOS7SignedIdentity(readCentOSHeader(t, "epel7-release-header.bin")); ok {
		t.Fatal("EPEL header must not pass the pinned CentOS signer check")
	}
	tampered := append([]byte(nil), bash...)
	tampered[100] ^= 1 // immutable-region index byte
	if _, _, _, ok := centOS7SignedIdentity(tampered); ok {
		t.Fatal("tampered signed header accepted")
	}
	badRegion := append([]byte(nil), bash...)
	badRegion[3] ^= 1
	if _, _, _, ok := centOS7SignedIdentity(badRegion); ok {
		t.Fatal("malformed immutable region accepted")
	}
	badPacket := append([]byte(nil), bash...)
	// RSAHEADER is outside the immutable region; locate and corrupt its packet.
	n := int(binary.BigEndian.Uint32(badPacket[:4]))
	entries := badPacket[8 : 8+n*16]
	data := badPacket[8+n*16:]
	for i := 0; i < len(entries); i += 16 {
		if binary.BigEndian.Uint32(entries[i:i+4]) == rpmTagRSAHeader {
			data[binary.BigEndian.Uint32(entries[i+8:i+12])] ^= 1
			break
		}
	}
	if _, _, _, ok := centOS7SignedIdentity(badPacket); ok {
		t.Fatal("invalid signature packet accepted")
	}
}

func TestCentOS7BaseManifestRequiresExactSignedHeaderAndIdentity(t *testing.T) {
	bash := readCentOSHeader(t, "centos7-bash-header.bin")
	original, _, _, ok := rpmImmutableRegion(bash)
	if !ok || !centOS7BaseHeaderAllowed(original, "bash", "4.2.46-34.el7", "x86_64") {
		t.Fatal("the verified Vault base RPM must match the installed immutable header")
	}
	if centOS7BaseHeaderAllowed(original, "other", "4.2.46-34.el7", "x86_64") ||
		centOS7BaseHeaderAllowed(original, "bash", "4.2.46-34.el7", "noarch") {
		t.Fatal("manifest hash alone must not promote a different package identity")
	}
	if name, _, _, ok := centOS7BaseSignedIdentity(bash); !ok || name != "bash" {
		t.Fatal("signed base RPM did not pass both provenance checks")
	}
	if parsed := parseCentOS7BaseManifest([]byte(strings.Replace(string(centOS7BaseManifestJSON),
		"https://vault.centos.org/7.9.2009/os/x86_64/", "https://vault.centos.org/7.9.2009/extras/x86_64/", 1))); parsed != nil {
		t.Fatal("a non-base repository cannot authorize the RHEL-derived approximation")
	}
	if parsed := parseCentOS7BaseManifest(append(append([]byte{}, centOS7BaseManifestJSON...), []byte("{}")...)); parsed != nil {
		t.Fatal("manifest with trailing JSON was accepted")
	}
}

func TestCentOS7SignedExtrasRemainsUnsupported(t *testing.T) {
	extras := readCentOSHeader(t, "centos7-extras-header.bin")
	name, _, _, ok := centOS7SignedIdentity(extras)
	if !ok || name != "WALinuxAgent" {
		t.Fatalf("Extras RPM must carry a genuine CentOS signature, name=%q verified=%v", name, ok)
	}
	if _, _, _, ok := centOS7BaseSignedIdentity(extras); ok {
		t.Fatal("a CentOS-signed Extras RPM cannot borrow base repository provenance")
	}
	root := writeRootfs(t, map[string]string{"etc/os-release": "ID=centos\nVERSION_ID=7\n"})
	dbPath := filepath.Join(root, rpmBDBPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, buildBDBHash(t, binary.LittleEndian, [][]byte{extras}), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New().Catalog(t.Context(), root)
	if err != nil || len(result.Components) != 1 || result.DistroResolved || result.UnsupportedDistro != "centos" || result.ApproximateDistro != "" {
		t.Fatalf("signed Extras catalog=%+v err=%v", result, err)
	}
	if identity := sbom.IdentityFromComponent(result.Components[0]); identity.Status != sbom.IdentityUnsupported {
		t.Fatalf("signed Extras acquired RHEL-derived advisory scope: %+v", identity)
	}
}

// appendUnsignedIdentityDribble adds identity tags after the immutable region.
// RPM's installed database can retain these unsigned dribbles beside the bytes
// covered by the header signature, so they must never influence the identity
// returned by centOS7SignedIdentity.
func appendUnsignedIdentityDribble(t *testing.T, blob []byte, tags []rpmTagEntry) []byte {
	t.Helper()
	if len(blob) < 8 {
		t.Fatal("signed header is too short")
	}
	n := int(binary.BigEndian.Uint32(blob[:4]))
	size := int(binary.BigEndian.Uint32(blob[4:8]))
	dataStart := 8 + n*16
	if n < 1 || size < 1 || dataStart+size != len(blob) {
		t.Fatalf("unexpected signed-header layout: n=%d size=%d len=%d", n, size, len(blob))
	}

	entries := blob[8:dataStart]
	data := blob[dataStart:]
	dribbleEntries := make([]byte, len(tags)*16)
	var dribbleData []byte
	for i, tag := range tags {
		if tag.typ != rpmTypeString {
			t.Fatalf("dribble tag %d has type %d, want string", tag.tag, tag.typ)
		}
		off := len(data) + len(dribbleData)
		entry := dribbleEntries[i*16:]
		binary.BigEndian.PutUint32(entry[:4], tag.tag)
		binary.BigEndian.PutUint32(entry[4:8], tag.typ)
		binary.BigEndian.PutUint32(entry[8:12], uint32(off))
		binary.BigEndian.PutUint32(entry[12:16], 1)
		dribbleData = append(dribbleData, tag.str...)
		dribbleData = append(dribbleData, 0)
	}

	out := make([]byte, 8+len(entries)+len(dribbleEntries)+len(data)+len(dribbleData))
	binary.BigEndian.PutUint32(out[:4], uint32(n+len(tags)))
	binary.BigEndian.PutUint32(out[4:8], uint32(size+len(dribbleData)))
	copy(out[8:], entries)
	copy(out[8+len(entries):], dribbleEntries)
	copy(out[8+len(entries)+len(dribbleEntries):], data)
	copy(out[8+len(entries)+len(dribbleEntries)+len(data):], dribbleData)
	return out
}

func TestCentOS7SignedIdentityBindsIdentityToImmutableBytesDespiteUnsignedDribble(t *testing.T) {
	dribbled := appendUnsignedIdentityDribble(t, readCentOSHeader(t, "centos7-bash-header.bin"), []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "forged-bash"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "999.0"},
		{tag: rpmTagRelease, typ: rpmTypeString, str: "attacker"},
		{tag: rpmTagArch, typ: rpmTypeString, str: "noarch"},
	})

	name, version, arch, ok := centOS7SignedIdentity(dribbled)
	if !ok || name != "bash" || version != "4.2.46-34.el7" || arch != "x86_64" {
		t.Fatalf("unsigned dribble changed signed identity: %q %q %q ok=%v", name, version, arch, ok)
	}
}

func TestCentOS7SignedIdentityRejectsShortReads(t *testing.T) {
	bash := readCentOSHeader(t, "centos7-bash-header.bin")
	n := int(binary.BigEndian.Uint32(bash[:4]))
	size := int(binary.BigEndian.Uint32(bash[4:8]))
	for _, cut := range []int{7, 8 + n*16 + size - 1, len(bash) - 1} {
		t.Run("cut", func(t *testing.T) {
			if _, _, _, ok := centOS7SignedIdentity(bash[:cut]); ok {
				t.Fatalf("short read at byte %d accepted", cut)
			}
		})
	}
}

func TestCatalogCentOS7MarksOnlyVerifiedBaseRPMForMatching(t *testing.T) {
	root := writeRootfs(t, map[string]string{"etc/os-release": "ID=centos\nVERSION_ID=7\n"})
	dbPath := filepath.Join(root, rpmBDBPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, buildBDBHash(t, binary.LittleEndian, [][]byte{readCentOSHeader(t, "centos7-bash-header.bin")}), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New().Catalog(t.Context(), root)
	if err != nil || len(result.Components) != 1 || result.DistroResolved || result.UnsupportedDistro != "centos" || result.ApproximateDistro != "centos-7" {
		t.Fatalf("catalog=%+v err=%v", result, err)
	}
	id := sbom.IdentityFromComponent(result.Components[0])
	if id.Ecosystem != "Red Hat:7" || id.Package != "bash" {
		t.Fatalf("verified catalog identity=%+v", id)
	}
	findings, err := ownadvisory.New(centOS7AdvisoryStore{}).Scan(t.Context(), &sbom.SBOM{Components: result.Components})
	if err != nil || len(findings) != 1 || findings[0].Ecosystem != "Red Hat:7" || findings[0].PackagePURL != result.Components[0].PURL {
		t.Fatalf("signed base RPM did not produce a RHEL-derived owned finding: %+v err=%v", findings, err)
	}

	root = writeRootfs(t, map[string]string{"etc/os-release": "ID=centos\nVERSION_ID=7\n"})
	dbPath = filepath.Join(root, rpmBDBPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, buildBDBHash(t, binary.LittleEndian, [][]byte{readCentOSHeader(t, "epel7-release-header.bin")}), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = New().Catalog(t.Context(), root)
	if err != nil || len(result.Components) != 1 || result.DistroResolved {
		t.Fatalf("EPEL catalog=%+v err=%v", result, err)
	}
	if id := sbom.IdentityFromComponent(result.Components[0]); id.Status == sbom.IdentityResolved {
		t.Fatalf("EPEL became matchable: %+v", id)
	}
}

func TestCatalogCentOS7RejectsAmbiguousRPMBackends(t *testing.T) {
	root := writeRPMRootfs(t, "ID=centos\nVERSION_ID=7\n")
	dbPath := filepath.Join(root, rpmBDBPath)
	if err := os.WriteFile(dbPath, buildBDBHash(t, binary.LittleEndian, [][]byte{readCentOSHeader(t, "centos7-bash-header.bin")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := New().Catalog(t.Context(), root); err == nil || len(result.Components) != 0 {
		t.Fatalf("sqlite decoy hid the BerkeleyDB inventory: result=%+v err=%v", result, err)
	}
}

func TestCatalogCentOS7DoesNotBorrowOriginForUnsignedDuplicateIdentity(t *testing.T) {
	root := writeRootfs(t, map[string]string{"etc/os-release": "ID=centos\nVERSION_ID=7\n"})
	dbPath := filepath.Join(root, rpmBDBPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	unsignedDuplicate := buildRPMHeader(t, true, []rpmTagEntry{
		{tag: rpmTagName, typ: rpmTypeString, str: "bash"},
		{tag: rpmTagVersion, typ: rpmTypeString, str: "4.2.46"},
		{tag: rpmTagRelease, typ: rpmTypeString, str: "34.el7"},
		{tag: rpmTagArch, typ: rpmTypeString, str: "x86_64"},
	})
	if err := os.WriteFile(dbPath, buildBDBHash(t, binary.LittleEndian, [][]byte{
		readCentOSHeader(t, "centos7-bash-header.bin"), unsignedDuplicate,
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := New().Catalog(t.Context(), root)
	if err != nil || len(result.Components) != 2 || result.DistroResolved || result.UnsupportedDistro != "centos" || result.ApproximateDistro != "" {
		t.Fatalf("catalog=%+v err=%v", result, err)
	}
	for _, component := range result.Components {
		identity := sbom.IdentityFromComponent(component)
		if identity.Package != "bash" || component.Version != "4.2.46-34.el7" {
			t.Fatalf("unexpected duplicate component: %+v identity=%+v", component, identity)
		}
		if identity.Status != sbom.IdentityUnsupported {
			t.Fatalf("ambiguous duplicate identity became matchable: %+v", identity)
		}
	}
	findings, err := ownadvisory.New(centOS7AdvisoryStore{}).Scan(t.Context(), &sbom.SBOM{Components: result.Components})
	if err != nil || len(findings) != 0 {
		t.Fatalf("ambiguous duplicate produced a RHEL-derived finding: %+v err=%v", findings, err)
	}
}

func TestCatalogCentOS7ReportsVerifiedAndUnsupportedPackagesTogether(t *testing.T) {
	root := writeRootfs(t, map[string]string{"etc/os-release": "ID=centos\nVERSION_ID=7\n"})
	dbPath := filepath.Join(root, rpmBDBPath)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, buildBDBHash(t, binary.LittleEndian, [][]byte{
		readCentOSHeader(t, "centos7-bash-header.bin"),
		readCentOSHeader(t, "epel7-release-header.bin"),
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := New().Catalog(t.Context(), root)
	if err != nil || len(result.Components) != 2 || result.DistroResolved || result.UnsupportedDistro != "centos" || result.ApproximateDistro != "centos-7" {
		t.Fatalf("mixed CentOS catalog=%+v err=%v", result, err)
	}
	findings, err := ownadvisory.New(centOS7AdvisoryStore{}).Scan(t.Context(), &sbom.SBOM{Components: result.Components})
	if err != nil || len(findings) != 1 || findings[0].Ecosystem != "Red Hat:7" {
		t.Fatalf("verified base package should still match: %+v err=%v", findings, err)
	}
}

func TestCentOS7PinnedKeyMatchesOfficialPublicKey(t *testing.T) {
	f, err := os.Open("testdata/centos-7-signing-key.asc")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	keys, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil || len(keys) != 1 {
		t.Fatalf("read official CentOS 7 key: keys=%d err=%v", len(keys), err)
	}
	key := keys[0].PrimaryKey
	const wantFingerprint = "6341AB2753D78A78A7C27BB124C6A8A7F4A80EB5"
	if got := stringUpperHex(key.Fingerprint); got != wantFingerprint {
		t.Fatalf("official CentOS 7 key fingerprint=%s, want %s", got, wantFingerprint)
	}
	public, ok := key.PublicKey.(*rsa.PublicKey)
	if !ok || public.E != centOS7Key.E || public.N.Cmp(centOS7Key.N) != 0 {
		t.Fatal("pinned CentOS 7 RSA key does not match audited public key")
	}
}

func stringUpperHex(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[2*i], out[2*i+1] = digits[v>>4], digits[v&0xf]
	}
	return string(out)
}
