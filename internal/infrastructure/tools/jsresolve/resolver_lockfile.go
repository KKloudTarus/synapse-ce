package jsresolve

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

// Importer context is what turns a multi-version ambiguity into a deterministic identity. When a
// repository installs two versions of the same package, the SBOM alone cannot say which one a given
// source file gets — but the lockfile can, because it records the resolution per importer (per workspace
// for pnpm, per install path for npm's hoisting rules).
//
// This reader is deliberately offline and read-only: it parses committed lockfiles and never runs a
// package manager. A lockfile it cannot interpret degrades coverage; it never guesses a version.

const (
	npmLockfileName   = "package-lock.json"
	npmShrinkwrapName = "npm-shrinkwrap.json"
	pnpmLockfileName  = "pnpm-lock.yaml"
	yarnLockfileName  = "yarn.lock"
)

// importerResolutions answers "which version of package P does importer directory D resolve to?".
type importerResolutions struct {
	// byImporter maps a repository-relative importer directory to package name -> resolved version.
	byImporter map[string]map[string]string
	// yarnActive records that a Yarn Berry lockfile was recognized and therefore may filter
	// component identity for dependencies joined to its descriptors.
	yarnActive bool
	// yarnRejectAll records a recognized but invalid Berry layout. Declared dependencies then fail
	// closed instead of falling back to SBOM-only certainty.
	yarnRejectAll bool
	// yarnInvalidByImporter records declared dependencies whose descriptor/locator evidence is unsafe.
	yarnInvalidByImporter map[string]map[string]struct{}
	// yarnIdentityPreserving records validated Yarn npm:<range> requests whose imported name remains
	// the package identity rather than becoming an npm alias target.
	yarnIdentityPreserving map[string]map[string]struct{}
	// present records that at least one supported lockfile was read.
	present bool
}

// selectVersion returns the version an importer resolves for a package name. It walks outward from the
// importer's own directory, mirroring how a workspace inherits the root install context.
func (i *importerResolutions) selectVersion(importerDir, packageName string) (string, bool) {
	if i == nil || !i.present {
		return "", false
	}
	dir := importerDir
	for {
		if versions, ok := i.byImporter[dir]; ok {
			if version, ok := versions[packageName]; ok && version != "" {
				return version, true
			}
		}
		if dir == "." || dir == "" {
			return "", false
		}
		parent := path.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// readImporterResolutions parses the committed lockfiles beneath root.
func (r *Resolver) readImporterResolutions(ctx context.Context, root string, packages []jsresolution.PackageMetadata, coverage *resolutionCoverageSink) *importerResolutions {
	out := &importerResolutions{
		byImporter:             map[string]map[string]string{},
		yarnInvalidByImporter:  map[string]map[string]struct{}{},
		yarnIdentityPreserving: map[string]map[string]struct{}{},
	}

	rootDir, err := os.OpenRoot(root)
	if err != nil {
		return out
	}
	defer func() { _ = rootDir.Close() }()

	packageManagerBytes := r.limits.maxLockfileBytes
	if r.inventory != nil && r.inventory.limits.maxMetadataFileBytes > 0 && r.inventory.limits.maxMetadataFileBytes < packageManagerBytes {
		packageManagerBytes = r.inventory.limits.maxMetadataFileBytes
	}
	rootManager := readRootPackageManagerFamily(rootDir, packageManagerBytes)
	_, shrinkwrapErr := rootDir.Lstat(npmShrinkwrapName)
	shrinkwrapPresent := shrinkwrapErr == nil
	for _, name := range []string{pnpmLockfileName, npmShrinkwrapName, npmLockfileName, yarnLockfileName} {
		if err := ctx.Err(); err != nil {
			return out
		}
		// Two independent precedence rules, both of which must hold (they arrived from #457 and #470
		// and conflicted textually, not semantically):
		//
		// 1. When the root explicitly selects Yarn, stale npm/pnpm lockfiles are not importer evidence
		//    for this install. Conversely, a yarn.lock only gains Yarn-specific semantics when the root
		//    packageManager actually selects Yarn; otherwise it remains unsupported/no-signal.
		// 2. npm-shrinkwrap.json has the same lock format as package-lock.json but is the authoritative
		//    committed lock when both exist. Never fall back to a stale package-lock after observing it.
		if rootManager == "yarn" && name != yarnLockfileName {
			continue
		}
		if name == npmLockfileName && shrinkwrapPresent {
			continue
		}
		data, ok := readBoundedLockfile(rootDir, name, r.limits.maxLockfileBytes)
		if !ok {
			if name == npmShrinkwrapName && shrinkwrapPresent {
				coverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageUnsupportedPackageManager, Path: name,
					Detail: "npm shrinkwrap is present but cannot be read safely within the lockfile budget",
				})
			}
			continue
		}
		switch name {
		case pnpmLockfileName:
			if parsePnpmImporters(data, out) {
				out.present = true
			} else {
				coverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageUnsupportedPackageManager, Path: name,
					Detail: "pnpm lockfile importers or v9 package/snapshot identities could not be interpreted safely, so per-importer version selection is unavailable",
				})
			}
		case npmShrinkwrapName, npmLockfileName:
			if parseNPMImporters(data, out) {
				out.present = true
			} else {
				coverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageUnsupportedPackageManager, Path: name,
					Detail: "npm lockfile could not be interpreted safely, so per-importer version selection is unavailable",
				})
			}
		case yarnLockfileName:
			if rootManager != "yarn" {
				coverage.add(jsresolution.CoverageIssue{
					Kind: jsresolution.CoverageUnsupportedPackageManager, Path: name,
					Detail: "yarn.lock importer selection requires package.json packageManager to select Yarn",
				})
				continue
			}
			if parseYarnImporters(ctx, data, packages, out, coverage, r.limits) {
				out.present = true
			}
		}
	}
	return out
}

func readRootPackageManagerFamily(rootDir *os.Root, maxBytes int64) string {
	data, ok := readBoundedLockfile(rootDir, "package.json", maxBytes)
	if !ok {
		return ""
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return ""
	}
	seen := false
	value := ""
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return ""
		}
		key, ok := keyToken.(string)
		if !ok {
			return ""
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return ""
		}
		if key != "packageManager" {
			continue
		}
		if seen {
			// Ambiguous manager selection must not activate Yarn-only semantics.
			return ""
		}
		seen = true
		if err := json.Unmarshal(raw, &value); err != nil {
			return ""
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return ""
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ""
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if at := strings.IndexByte(value, '@'); at > 0 {
		value = value[:at]
	}
	switch value {
	case "npm", "pnpm", "yarn":
		return value
	default:
		return ""
	}
}

// readBoundedLockfile reads a lockfile through the confined root handle, refusing a symlink, a
// non-regular file, or a file past the byte budget.
func readBoundedLockfile(rootDir *os.Root, name string, maxBytes int64) ([]byte, bool) {
	info, err := rootDir.Lstat(name)
	if err != nil || info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxBytes {
		return nil, false
	}
	f, err := rootDir.Open(name)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, false
	}
	return data, true
}

// parsePnpmImporters reads the `importers:` block of a pnpm lockfile, which maps each workspace
// directory to the exact version it resolves for every declared dependency. For pnpm v9, importer
// evidence is accepted only when the same npm identity exists in both `packages` and `snapshots`.
func parsePnpmImporters(data []byte, out *importerResolutions) bool {
	lock := struct {
		LockfileVersion string `yaml:"lockfileVersion"`
		Importers       map[string]struct {
			Dependencies         map[string]pnpmLockDep `yaml:"dependencies"`
			DevDependencies      map[string]pnpmLockDep `yaml:"devDependencies"`
			OptionalDependencies map[string]pnpmLockDep `yaml:"optionalDependencies"`
		} `yaml:"importers"`
		Dependencies    map[string]pnpmLockDep `yaml:"dependencies"`
		DevDependencies map[string]pnpmLockDep `yaml:"devDependencies"`
		Packages        map[string]any         `yaml:"packages"`
		Snapshots       map[string]any         `yaml:"snapshots"`
	}{}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return false
	}

	v9 := pnpmHasSnapshotGraph(lock.Snapshots, lock.LockfileVersion)
	packageIdentities := pnpmIdentitySet(lock.Packages)
	snapshotIdentities := pnpmIdentitySet(lock.Snapshots)
	selected := map[string]map[string]string{}
	invalidV9Evidence := false

	record := func(dir string, groups ...map[string]pnpmLockDep) {
		normalized := normalizeImporterDir(dir)
		for _, group := range groups {
			for name, dep := range group {
				rawVersion := strings.TrimSpace(dep.Version)
				if strings.HasPrefix(rawVersion, "link:") || strings.HasPrefix(rawVersion, "file:") {
					continue
				}
				version, ok := pnpmResolvedBaseVersion(rawVersion)
				if !ok {
					if v9 && rawVersion != "" {
						invalidV9Evidence = true
					}
					continue
				}
				if v9 {
					identity := pnpmPackageIdentityKey(name, version)
					if _, ok := packageIdentities[identity]; !ok {
						invalidV9Evidence = true
						continue
					}
					if _, ok := snapshotIdentities[identity]; !ok {
						invalidV9Evidence = true
						continue
					}
				}
				if selected[normalized] == nil {
					selected[normalized] = map[string]string{}
				}
				selected[normalized][name] = version
			}
		}
	}

	for dir, importer := range lock.Importers {
		record(dir, importer.Dependencies, importer.DevDependencies, importer.OptionalDependencies)
	}
	// A single-package repository in older supported layouts may put dependencies at the top level.
	record(".", lock.Dependencies, lock.DevDependencies)

	if v9 && (len(lock.Packages) == 0 || len(lock.Snapshots) == 0 || invalidV9Evidence) {
		return false
	}
	if len(selected) == 0 {
		return false
	}
	for dir, versions := range selected {
		if out.byImporter[dir] == nil {
			out.byImporter[dir] = map[string]string{}
		}
		for name, version := range versions {
			out.byImporter[dir][name] = version
		}
	}
	return true
}

type pnpmLockDep struct {
	Version string `yaml:"version"`
}

// pnpmHasSnapshotGraph reports whether this lockfile must satisfy the packages x snapshots identity
// cross-check.
//
// The trigger is STRUCTURAL: a `snapshots:` section is present. It deliberately does not depend on
// matching a known `lockfileVersion` string, because that fails OPEN on format drift — every check
// built on top of it silently disappears the day pnpm bumps the number, with no error and no coverage
// issue, which is worse than a gap somebody knows about. Verified: with a version-literal gate,
// identical dangling evidence resolved to `ambiguous` under '9.0' and to a `component` naming a version
// present in NEITHER section under '9.1' and '10.0'.
//
// The version is still consulted as a fallback so a declared v9 lockfile with an EMPTY or missing
// snapshots section is refused rather than quietly treated as a pre-v9 layout.
func pnpmHasSnapshotGraph(snapshots map[string]any, rawVersion string) bool {
	if snapshots != nil {
		return true
	}
	value := strings.Trim(strings.TrimSpace(rawVersion), `"'`)
	major, _, _ := strings.Cut(value, ".")
	if n, err := strconv.Atoi(major); err == nil {
		return n >= 9
	}
	return false
}

func pnpmIdentitySet(entries map[string]any) map[string]struct{} {
	out := make(map[string]struct{}, len(entries))
	for key := range entries {
		name, version, ok := pnpmV9PackageIdentity(key)
		if !ok {
			continue
		}
		out[pnpmPackageIdentityKey(name, version)] = struct{}{}
	}
	return out
}

func pnpmV9PackageIdentity(key string) (string, string, bool) {
	key = strings.TrimSpace(key)
	baseKey := key
	if peer := strings.IndexByte(baseKey, '('); peer >= 0 {
		if !pnpmV9ValidPeerSuffix(baseKey[peer:]) {
			return "", "", false
		}
		baseKey = strings.TrimSpace(baseKey[:peer])
	} else if strings.ContainsRune(baseKey, ')') {
		return "", "", false
	}
	separator := strings.LastIndexByte(baseKey, '@')
	if separator <= 0 || separator == len(baseKey)-1 {
		return "", "", false
	}
	name, err := jsresolution.NormalizePackageName(baseKey[:separator])
	if err != nil {
		return "", "", false
	}
	version, ok := pnpmResolvedBaseVersion(baseKey[separator+1:])
	if !ok {
		return "", "", false
	}
	return name, version, true
}

func pnpmResolvedBaseVersion(value string) (string, bool) {
	value = strings.TrimSpace(value)
	base := value
	if peer := strings.IndexByte(base, '('); peer >= 0 {
		if !pnpmV9ValidPeerSuffix(base[peer:]) {
			return "", false
		}
		base = strings.TrimSpace(base[:peer])
	} else if strings.ContainsRune(base, ')') {
		return "", false
	}
	if !sbom.IsResolvedVersion(base) {
		return "", false
	}
	return base, true
}

func pnpmV9ValidPeerSuffix(suffix string) bool {
	if suffix == "" || suffix[0] != '(' {
		return false
	}
	depth := 0
	groupHasContent := false
	for _, r := range suffix {
		switch r {
		case '(':
			if depth == 0 {
				groupHasContent = false
			}
			depth++
		case ')':
			if depth <= 0 || !groupHasContent {
				return false
			}
			depth--
		default:
			if depth == 0 {
				return false
			}
			if !strings.ContainsRune(" \t\r\n", r) {
				groupHasContent = true
			}
		}
	}
	return depth == 0
}

func pnpmPackageIdentityKey(name, version string) string {
	return name + "\x00" + version
}

// npmLockPackage is the subset of a lockfileVersion 2/3 `packages` entry this reader needs.
type npmLockPackage struct {
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	DevDeps      map[string]string `json:"devDependencies"`
	OptionalDeps map[string]string `json:"optionalDependencies"`
	Link         bool              `json:"link"`
	Resolved     string            `json:"resolved"`
}

// parseNPMImporters reads a lockfileVersion 2/3 `packages` map and resolves, for each importer, the
// install that satisfies each declared dependency using npm's nearest-wins hoisting rule.
func parseNPMImporters(data []byte, out *importerResolutions) bool {
	if err := validateNoDuplicateJSONKeys(data); err != nil {
		return false
	}
	lock := struct {
		LockfileVersion int                       `json:"lockfileVersion"`
		Packages        map[string]npmLockPackage `json:"packages"`
	}{}
	if err := json.Unmarshal(data, &lock); err != nil {
		return false
	}
	if len(lock.Packages) == 0 {
		// lockfileVersion 1 has no `packages` map and no install paths, so hoisting is not recoverable.
		return false
	}

	// An importer is the root project ("") or a workspace, which appears as a bare non-node_modules key.
	for key, pkg := range lock.Packages {
		if strings.Contains(key, "node_modules/") {
			continue
		}
		dir := normalizeImporterDir(key)
		for _, group := range []map[string]string{pkg.Dependencies, pkg.DevDeps, pkg.OptionalDeps} {
			for name := range group {
				installPath := resolveHoistedInstall(key, name, lock.Packages)
				if installPath == "" {
					continue
				}
				installed := lock.Packages[installPath]
				if installed.Link || !sbom.IsResolvedVersion(installed.Version) {
					// A link points at a local workspace, not a registry version.
					continue
				}
				if out.byImporter[dir] == nil {
					out.byImporter[dir] = map[string]string{}
				}
				out.byImporter[dir][name] = installed.Version
			}
		}
	}
	return len(out.byImporter) > 0
}

// resolveHoistedInstall applies npm's resolution rule: search the importer's own node_modules first,
// then each ancestor install context outward, ending at the root. The nearest match wins. It returns ""
// when no installed package satisfies the name, which is treated as no signal rather than a guess.
func resolveHoistedInstall(fromPath, depName string, packages map[string]npmLockPackage) string {
	cur := fromPath
	for {
		candidate := "node_modules/" + depName
		if cur != "" {
			candidate = cur + "/node_modules/" + depName
		}
		if _, ok := packages[candidate]; ok {
			return candidate
		}
		if cur == "" {
			return ""
		}
		if idx := strings.LastIndex(cur, "/node_modules/"); idx >= 0 {
			cur = cur[:idx]
			continue
		}
		cur = ""
	}
}

// normalizeImporterDir converts a lockfile importer key to the repository-relative directory form the
// resolver uses for module paths.
func normalizeImporterDir(raw string) string {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimPrefix(trimmed, "./")
	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return "."
	}
	return path.Clean(trimmed)
}

// disambiguateByImporter selects the single candidate whose version the importer resolves. It returns
// false when the importer offers no signal or the selected version matches no candidate, so ambiguity is
// preserved rather than resolved by guesswork.
func disambiguateByImporter(
	candidates []jsresolution.PackageIdentity,
	resolutions *importerResolutions,
	packages []jsresolution.PackageMetadata,
	importer, packageName string,
) (jsresolution.PackageIdentity, bool) {
	if len(candidates) < 2 || resolutions == nil || !resolutions.present {
		return jsresolution.PackageIdentity{}, false
	}
	importerDir := "."
	if owner, ok := packageForRepositoryTarget(packages, importer); ok && owner.Path != "" {
		importerDir = owner.Path
	}
	version, ok := resolutions.selectVersion(importerDir, packageName)
	if !ok {
		return jsresolution.PackageIdentity{}, false
	}
	var selected []jsresolution.PackageIdentity
	for _, candidate := range candidates {
		if candidate.Version == version {
			selected = append(selected, candidate)
		}
	}
	if len(selected) != 1 {
		return jsresolution.PackageIdentity{}, false
	}
	return selected[0], true
}
