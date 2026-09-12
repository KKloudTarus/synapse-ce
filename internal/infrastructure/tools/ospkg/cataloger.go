// Package ospkg catalogs installed OS packages from a materialized image root filesystem: Debian/Ubuntu dpkg
// (/var/lib/dpkg/status), Alpine apk (/lib/apk/db/installed), and RHEL-family rpm (/var/lib/rpm/rpmdb.sqlite),
// with the distro release read from /etc/os-release. It is the OWNED (detection-independent) alternative to relying on the SBOM generator for
// OS packages, and emits components tagged with a Syft-style "distro" qualifier so the existing advisory
// matcher keys them to the right OS ecosystem. It only READS the rootfs (already assembled within the
// workspace); the databases are UNTRUSTED, so: reads are streamed + bounded (size, line, and package caps)
// and cancellable, every leaf is regular-file-guarded (no symlink follow out of the rootfs), package
// name/version are percent-encoded into the PURL (so a crafted value cannot make the PURL ambiguous or
// smuggle a qualifier) while the raw values are kept for advisory matching, and the distro tag is applied
// ONLY for a release the matcher can key (a lying/garbled os-release yields an UNRESOLVED result, warned
// upstream, never a silent zero-match).
package ospkg

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	maxDBBytes    = 64 << 20  // total bytes read from one DB (bomb guard)
	maxDBLine     = 1 << 20   // max single line (a long Description); a longer line abandons the DB
	maxLines      = 5_000_000 // total lines scanned per DB (blank-line-flood guard)
	maxPackages   = 200_000   // emitted-package cap per DB
	maxFieldChars = 512       // clip an over-long name/version (rune-safe) before it enters a PURL
)

// DB paths (relative to a rootfs) this cataloger reads. Exported so a coverage probe (the fleet host
// collector) can enumerate exactly what is read without re-hardcoding the list and silently drifting.
const (
	dpkgDBPath = "var/lib/dpkg/status"
	apkDBPath  = "lib/apk/db/installed"
	rpmDBPath  = "var/lib/rpm/rpmdb.sqlite" // RHEL9+/Fedora/UBI9 sqlite backend
	rpmBDBPath = "var/lib/rpm/Packages"     // RHEL<=8/CentOS/UBI8/Amazon Linux 2 BerkeleyDB backend
	// ndb backend (openSUSE/SLE, rpm >= 4.15). openSUSE Leap relocates the rpmdb under
	// /usr/lib/sysimage/rpm and symlinks /var/lib/rpm to it, so both locations are probed.
	rpmNDBPath         = "var/lib/rpm/Packages.db"
	rpmNDBSysimagePath = "usr/lib/sysimage/rpm/Packages.db"
)

// SupportedDBPaths returns the rootfs-relative OS package database paths Catalog reads, in a fresh
// slice. It is the single source of truth for "which databases does the engine know about", so the host
// coverage probe never claims a DB the cataloger cannot read. All three rpm backends are covered: sqlite
// (rpmDBPath), BerkeleyDB (rpmBDBPath), and ndb (rpmNDBPath and its relocated openSUSE location).
func SupportedDBPaths() []string {
	return []string{dpkgDBPath, apkDBPath, rpmDBPath, rpmBDBPath, rpmNDBPath, rpmNDBSysimagePath}
}

// debianFamilyIDs are the dpkg os-release IDs the advisory matcher can key (osDistroEcosystem handles Debian +
// Ubuntu); only these get a distro tag, so any other/garbled/mismatched ID yields an unresolved result.
var debianFamilyIDs = map[string]bool{"debian": true, "ubuntu": true}

// Cataloger implements ports.OSPackageCataloger over a materialized image rootfs.
type Cataloger struct{}

// New returns an OS-package cataloger.
func New() *Cataloger { return &Cataloger{} }

var _ ports.OSPackageCataloger = (*Cataloger)(nil)

// Catalog reads the OS-package databases under rootfsDir. Best-effort per ecosystem (an absent/unreadable DB
// contributes nothing); returns an error only on context cancellation. DistroResolved is false when packages
// were emitted but the release could not be keyed to an advisory ecosystem.
func (Cataloger) Catalog(ctx context.Context, rootfsDir string) (ports.OSPackageResult, error) {
	if err := ctx.Err(); err != nil {
		return ports.OSPackageResult{}, err
	}
	if strings.TrimSpace(rootfsDir) == "" {
		return ports.OSPackageResult{}, nil
	}
	id, versionID := osRelease(rootfsDir)
	res := ports.OSPackageResult{DistroResolved: true}

	// dpkg (Debian family): resolvable only when os-release ID is debian/ubuntu, else emit with no distro tag.
	debNS, debTag := "debian", ""
	if debianFamilyIDs[id] && versionID != "" {
		debNS, debTag = id, id+"-"+versionID
	}
	comps, err := parseOSDB(ctx, filepath.Join(rootfsDir, dpkgDBPath), dpkgFieldKeys, dpkgExtract, "deb", debNS, debTag)
	if err != nil {
		return ports.OSPackageResult{}, err
	}
	if len(comps) > 0 {
		res.Components = append(res.Components, comps...)
		if debTag == "" {
			res.DistroResolved = false
		}
	}

	// apk (Alpine / Wolfi / Chainguard): Alpine keys by its release (alpine-3.19), while Wolfi and Chainguard
	// are rolling (keyed by family name alone). Each resolves to the ecosystem the owned apk secdb feed writes.
	apkNS, apkTag := "alpine", ""
	switch id {
	case "alpine":
		if versionID != "" {
			apkTag = "alpine-" + versionID
		}
	case "wolfi", "chainguard":
		apkNS, apkTag = id, id // rolling: the family name is the whole distro key, with no release version
	}
	comps, err = parseOSDB(ctx, filepath.Join(rootfsDir, apkDBPath), apkFieldKeys, apkExtract, "apk", apkNS, apkTag)
	if err != nil {
		return ports.OSPackageResult{}, err
	}
	if len(comps) > 0 {
		res.Components = append(res.Components, comps...)
		if apkTag == "" {
			res.DistroResolved = false
		}
	}

	// rpm (RHEL/Fedora/SUSE family): the distro qualifier is set for any rpm-family id (inventory), but only the
	// ids osDistroEcosystem keys (Rocky/AlmaLinux/Oracle, and openSUSE Leap) with a non-empty major version
	// count as resolved – RHEL/CentOS/Fedora use module-qualified or uncertain OSV keys, so they are emitted but
	// flagged unresolved (surfaced upstream, never a silent zero-match). rpmComponents tries the sqlite backend,
	// then the owned BerkeleyDB backend (RHEL<=8/UBI8), then the owned ndb backend (openSUSE/SLE), so every rpm
	// rootfs is cataloged.
	rpmNS, rpmTag := "rhel", ""
	rpmResolved := false
	if id != "" {
		rpmNS = id
		if versionID != "" {
			rpmTag = id + "-" + versionID
			// Mirror osDistroEcosystem, which keys on the major (VERSION_ID up to the first '.'): a clean-but-
			// empty major (e.g. VERSION_ID=".3", which isCleanToken admits) maps to nothing. Require a non-empty
			// major here too, so this resolved flag can never disagree with the mapping – a disagreement would be
			// exactly the silent zero-match (resolved=true yet ecosystem="") this flag exists to prevent.
			major := versionID
			if i := strings.IndexByte(versionID, '.'); i >= 0 {
				major = versionID[:i]
			}
			rpmResolved = rpmMatchableIDs[id] && major != ""
			if id == "opensuse-leap" || id == "sles" {
				// openSUSE Leap (openSUSE:15.6) and SUSE Linux Enterprise (SUSE:15.6, keyed per service pack) key
				// on major.minor, not the major alone, so a bare or trailing-dot VERSION_ID must NOT resolve: it
				// would set DistroResolved=true yet derive a key the feed never wrote (openSUSE:15 / SUSE:15),
				// exactly the silent zero-match this flag prevents. A genuine Leap/SLE os-release always carries
				// major.minor (e.g. SLES VERSION_ID="15.6").
				_, minor, hasMinor := strings.Cut(versionID, ".")
				rpmResolved = rpmResolved && hasMinor && minor != ""
			}
		}
	}
	rpmComps, err := rpmComponents(ctx, rootfsDir, rpmNS, rpmTag)
	if err != nil { // only a context cancellation; a hostile/malformed DB degrades to no components
		return ports.OSPackageResult{}, err
	}
	if len(rpmComps) > 0 {
		res.Components = append(res.Components, rpmComps...)
		if !rpmResolved {
			res.DistroResolved = false
		}
	}
	return res, nil
}

// rpmMatchableIDs are the rpm-family os-release IDs osDistroEcosystem can key to an advisory ecosystem: RHEL
// (rhel/redhat -> "Red Hat:<major>", served by the owned Red Hat CSAF feed), the Rocky/AlmaLinux/Oracle
// rebuilds (keyed "<Name>:<major>" by their own errata), Amazon Linux (amzn/amazon -> "Amazon Linux:<release>",
// served by the owned Amazon updateinfo feed), Fedora (fedora -> "Fedora:<major>", served by the owned Fedora
// updateinfo feed), openSUSE Leap (opensuse-leap -> "openSUSE:<major.minor>", owned openSUSE OVAL feed), and
// SUSE Linux Enterprise (sles -> "SUSE:<major.minor>" per service pack, owned SLE OVAL feed). This set must
// stay in lockstep with osDistroEcosystem: an id is listed only once its ecosystem mapping AND feed exist, so
// DistroResolved never claims a keying the matcher cannot make. CentOS (Stream drifts ahead of RHEL, so a RHEL
// fixed NEVR would false-match a Stream package) and openSUSE Tumbleweed (rolling, no per-release feed) stay
// OFF, so their rpm packages are cataloged for inventory but honestly flagged unresolved.
var rpmMatchableIDs = map[string]bool{"rhel": true, "redhat": true, "rocky": true, "almalinux": true, "alma": true, "ol": true, "oracle": true, "amzn": true, "amazon": true, "fedora": true, "opensuse-leap": true, "sles": true}

// dpkgFieldKeys / apkFieldKeys are the ONLY stanza keys each parser reads. parseOSDB stores only these, so a
// stanza with millions of distinct junk keys cannot grow the per-stanza map (keeps memory O(1) per stanza).
var (
	dpkgFieldKeys = map[string]bool{"Package": true, "Status": true, "Version": true, "Architecture": true, "Source": true}
	apkFieldKeys  = map[string]bool{"P": true, "V": true, "A": true}
)

// dpkgExtract pulls (name, version, arch, upstream) from a dpkg stanza; only "install ok installed" is
// present. upstream is the deb PURL "upstream=" value derived from the "Source:" field (see
// dpkgSourceQualifier) so a binary whose SOURCE package name differs still matches its source-keyed advisory.
func dpkgExtract(f map[string]string) (name, version, arch, upstream string, ok bool) {
	if !strings.Contains(f["Status"], "install ok installed") {
		return "", "", "", "", false
	}
	name, version, arch = f["Package"], f["Version"], f["Architecture"]
	return name, version, arch, dpkgSourceQualifier(f["Source"], name), true
}

// dpkgSourceQualifier turns a dpkg "Source:" field into the deb PURL "upstream=" value the advisory matcher
// reads. A Debian/Ubuntu security advisory is keyed by the SOURCE package (one openssl advisory covers the
// libssl3, libcrypto3, … binaries built from it), so a binary whose source name differs never matches the
// advisory by its own name. The field is "<source>" or "<source> (<source-version>)"; dpkg OMITS it when the
// source name and version equal the binary's. Returns the source name, plus "@<source-version>" when the
// field carries a distinct source version (a binNMU makes the binary version "<src>+bN" while the advisory
// ranges live in source-version space). Returns "" when there is no DISTINCT source name (the binary name is
// already the match key, matched with the binary version by the primary lookup).
func dpkgSourceQualifier(source, binName string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	name, version := source, ""
	if i := strings.IndexByte(source, '('); i >= 0 {
		name = strings.TrimSpace(source[:i])
		if j := strings.IndexByte(source[i+1:], ')'); j >= 0 {
			version = strings.TrimSpace(source[i+1 : i+1+j])
		}
	}
	if name == "" || name == binName {
		return "" // no distinct source package; the binary name already IS the match key
	}
	if version != "" {
		return name + "@" + version
	}
	return name
}

// apkExtract pulls (name, version, arch) from an apk stanza (single-letter keys). No upstream: the apk
// secdb matcher is keyed on the package name the apk DB carries.
func apkExtract(f map[string]string) (name, version, arch, upstream string, ok bool) {
	return f["P"], f["V"], f["A"], "", true
}

// parseOSDB streams a Debian/apk control DB (stanzas separated by a blank line, "Key: Value" lines) into
// components. Streaming keeps memory O(1) per stanza; the size/line/package caps + periodic ctx check bound a
// hostile DB. A missing/irregular/symlinked path or an over-long line yields no components (best-effort).
func parseOSDB(ctx context.Context, path string, fieldKeys map[string]bool, extract func(map[string]string) (string, string, string, string, bool), typ, namespace, tag string) ([]sbom.Component, error) {
	fi, err := os.Lstat(path) // regular-file guard: never follow a symlinked DB out of the rootfs
	if err != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(io.LimitReader(f, maxDBBytes))
	sc.Buffer(make([]byte, 0, 64*1024), maxDBLine)
	var out []sbom.Component
	cur := map[string]string{}
	lines := 0
	flush := func() {
		defer func() { cur = map[string]string{} }()
		if len(cur) == 0 || len(out) >= maxPackages { // keep maxPackages an exact upper bound
			return
		}
		if name, version, arch, upstream, ok := extract(cur); ok {
			if c, ok := osComponent(typ, namespace, name, version, arch, tag, upstream); ok {
				c.Location = path // the package DB's path, so the component attributes to the DB's image layer
				out = append(out, c)
			}
		}
	}
	for sc.Scan() {
		lines++
		if lines > maxLines || len(out) >= maxPackages {
			break
		}
		if lines&0x3fff == 0 { // ~every 16k lines: honor cancellation of a large parse
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" { // stanza boundary
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' { // continuation line (dpkg multi-line value): not a field we read
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		// Store ONLY the keys the extractor reads, so a stanza of millions of junk keys can't grow the map.
		if key := strings.TrimSpace(line[:i]); fieldKeys[key] && cur[key] == "" {
			cur[key] = strings.TrimSpace(line[i+1:])
		}
	}
	flush()
	// A scanner error (e.g. a line over maxDBLine) abandons the DB rather than emitting a partial/odd set.
	if sc.Err() != nil {
		return nil, nil
	}
	return out, nil
}

// osComponent builds an OS-package component with a spec-encoded PURL. The name/version are percent-encoded
// into the PURL (so an attacker-authored value cannot make the name/version boundary ambiguous or inject a
// qualifier) but kept RAW in Name/Version, which is what the advisory matcher compares. Returns ok=false when
// the name/version is empty or carries a control character. The distro qualifier is set only for a resolvable
// release, so a match is attempted only against a real OS ecosystem.
func osComponent(typ, namespace, name, version, arch, tag, upstream string) (sbom.Component, bool) {
	name, version = cleanField(name), cleanField(version)
	if name == "" || version == "" {
		return sbom.Component{}, false
	}
	purl := "pkg:" + typ + "/" + namespace + "/" + purlEncode(name) + "@" + purlEncode(version)
	var q []string
	if a := cleanField(arch); a != "" {
		q = append(q, "arch="+purlEncode(a))
	}
	if tag != "" {
		q = append(q, "distro="+purlEncode(tag))
	}
	// upstream=<source>[@<source-version>]: the SOURCE package a Debian/Ubuntu advisory is keyed by, so a
	// binary whose source name differs matches its source-keyed advisory (the matcher reads this qualifier).
	// The whole value is percent-encoded, so a hostile Source field cannot inject a qualifier (@ -> %40).
	if up := cleanField(upstream); up != "" {
		q = append(q, "upstream="+purlEncode(up))
	}
	if len(q) > 0 {
		purl += "?" + strings.Join(q, "&")
	}
	return sbom.Component{Name: name, Version: version, PURL: purl, Scope: sbom.ScopeProduction}, true
}

// osRelease reads <rootfs>/etc/os-release (falling back to /usr/lib/os-release) and returns the lowercased
// distro ID and VERSION_ID, both validated to clean tokens (so a crafted os-release cannot inject into a
// distro qualifier). Either is "" when unavailable/invalid.
func osRelease(rootfsDir string) (id, versionID string) {
	data := readBounded(filepath.Join(rootfsDir, "etc/os-release"), 64<<10)
	if len(data) == 0 {
		data = readBounded(filepath.Join(rootfsDir, "usr/lib/os-release"), 64<<10)
	}
	if len(data) == 0 {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "ID":
			id = strings.ToLower(strings.TrimSpace(v))
		case "VERSION_ID":
			versionID = v
		}
	}
	if !isCleanToken(id) {
		id = ""
	}
	if !isCleanToken(versionID) {
		versionID = ""
	}
	return id, versionID
}

// cleanField trims a field, rejects it if it carries a control character (a line-parsed value should not),
// and rune-safe-clips it to maxFieldChars.
func cleanField(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	if len(s) > maxFieldChars {
		r := []rune(s)
		if len(r) > maxFieldChars {
			s = string(r[:maxFieldChars])
		}
	}
	return s
}

// purlEncode percent-encodes a PURL segment: RFC 3986 unreserved bytes pass through, every other byte becomes
// %XX (byte-wise, so multibyte UTF-8 is encoded canonically). This makes the emitted PURL unambiguous + free
// of injected separators/qualifiers regardless of the attacker-authored input.
func purlEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// isCleanToken reports whether an os-release ID / VERSION_ID is a safe distro-tag token (alphanumeric, dot,
// dash, underscore, <=64 chars).
func isCleanToken(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// readBounded reads a small regular file up to max bytes (for the tiny os-release; the large package DBs are
// streamed by parseOSDB). Missing/irregular/symlink path or error → nil.
func readBounded(path string, max int64) []byte {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, max))
	if err != nil {
		return nil
	}
	return data
}
