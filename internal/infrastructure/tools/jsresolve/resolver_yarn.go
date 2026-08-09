package jsresolve

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

type yarnLockEntry struct {
	descriptors    []string
	version        string
	resolution     string
	versionSeen    bool
	resolutionSeen bool
	malformed      bool
}

type yarnDescriptorVersionIndex struct {
	versions map[string][]string
	invalid  map[string]struct{}
}

type yarnLockState uint8

const (
	yarnLockUnsupported yarnLockState = iota
	yarnLockInvalid
	yarnLockSupported
)

// parseYarnImporters recovers importer-specific versions from a committed Yarn
// Berry lockfile by joining each first-party manifest request to the exact
// descriptor recorded in yarn.lock. It never evaluates semver ranges: the
// descriptor string itself is the join key, which keeps selection deterministic
// and source-only.
func parseYarnImporters(
	ctx context.Context,
	data []byte,
	packages []jsresolution.PackageMetadata,
	out *importerResolutions,
	coverage *resolutionCoverageSink,
	limits resolverLimits,
) bool {
	index, state := parseYarnDescriptorVersions(ctx, data, coverage, limits)
	switch state {
	case yarnLockUnsupported:
		return false
	case yarnLockInvalid:
		out.yarnActive = true
		out.yarnRejectAll = true
		return false
	default:
		out.yarnActive = true
	}

	workspaceNames := make(map[string]struct{})
	for _, pkg := range packages {
		if pkg.Workspace && pkg.Name != "" {
			workspaceNames[pkg.Name] = struct{}{}
		}
	}

	for _, pkg := range packages {
		if ctx.Err() != nil {
			return false
		}
		if pkg.Path != "" && pkg.Path != "." && !pkg.Workspace {
			continue
		}
		importer := normalizeImporterDir(pkg.Path)

		for _, dep := range pkg.Dependencies {
			name := dep.Name
			request := strings.TrimSpace(dep.Spec)
			if request == "" || strings.HasPrefix(request, "workspace:") {
				continue
			}
			if _, local := workspaceNames[name]; local {
				// A same-name workspace keeps local-vs-registry identity ambiguous in
				// the current resolver. Do not let Yarn lock evidence force it external.
				continue
			}
			if !yarnRequestIsNPMRegistry(name, request) {
				continue
			}

			versions, invalid := yarnResolvedVersions(index, name, request)
			if invalid {
				markYarnImporterInvalid(out, importer, name)
				coverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageUnsupportedMetadata,
					Path:   yarnLockfileName,
					Detail: fmt.Sprintf("yarn.lock has inconsistent metadata for %s@%s", name, boundedYarnText(request)),
				})
				continue
			}
			if len(versions) == 0 {
				markYarnImporterInvalid(out, importer, name)
				coverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageUnsupportedMetadata,
					Path:   yarnLockfileName,
					Detail: fmt.Sprintf("yarn.lock has no resolved descriptor for %s@%s", name, boundedYarnText(request)),
				})
				continue
			}
			if len(versions) != 1 {
				markYarnImporterInvalid(out, importer, name)
				coverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageUnsupportedMetadata,
					Path:   yarnLockfileName,
					Detail: fmt.Sprintf("yarn.lock resolves %s@%s to more than one version", name, boundedYarnText(request)),
				})
				continue
			}
			if out.byImporter[importer] == nil {
				out.byImporter[importer] = map[string]string{}
			}
			out.byImporter[importer][name] = versions[0]
			if yarnNPMProtocolKeepsIdentity(name, request) {
				if out.yarnIdentityPreserving[importer] == nil {
					out.yarnIdentityPreserving[importer] = map[string]struct{}{}
				}
				out.yarnIdentityPreserving[importer][name] = struct{}{}
			}
		}
	}
	return true
}

func markYarnImporterInvalid(out *importerResolutions, importer, name string) {
	if out.yarnInvalidByImporter[importer] == nil {
		out.yarnInvalidByImporter[importer] = map[string]struct{}{}
	}
	out.yarnInvalidByImporter[importer][name] = struct{}{}
}

// yarnImporterEvidence reports lockfile evidence only for a dependency that the
// nearest first-party package actually declares. Yarn descriptors are not
// importer records by themselves; the manifest-to-descriptor join is what makes
// this signal importer-specific.
func yarnImporterEvidence(
	packages []jsresolution.PackageMetadata,
	importer, packageName string,
	resolutions *importerResolutions,
) (version string, selected, rejected bool) {
	if resolutions == nil || !resolutions.yarnActive {
		return "", false, false
	}
	owner, ok := packageForRepositoryTarget(packages, importer)
	if !ok {
		return "", false, false
	}
	if _, declared := declaredSpecFor(packages, importer, packageName); !declared {
		return "", false, false
	}
	if resolutions.yarnRejectAll {
		return "", false, true
	}
	dir := normalizeImporterDir(owner.Path)
	if invalid := resolutions.yarnInvalidByImporter[dir]; invalid != nil {
		if _, bad := invalid[packageName]; bad {
			return "", false, true
		}
	}
	if versions := resolutions.byImporter[dir]; versions != nil {
		if version := versions[packageName]; version != "" {
			return version, true, false
		}
	}
	return "", false, false
}

// resolveDeclaredIdentityWithLockfile preserves Yarn's identity-preserving
// npm:<range> protocol only when a validated Berry descriptor was observed for
// the importer's declared dependency. npm/no-manager alias semantics therefore
// remain unchanged.
func resolveDeclaredIdentityWithLockfile(
	packages []jsresolution.PackageMetadata,
	importer, packageName string,
	resolutions *importerResolutions,
) (string, string) {
	if resolutions != nil {
		if owner, ok := packageForRepositoryTarget(packages, importer); ok {
			dir := normalizeImporterDir(owner.Path)
			if names := resolutions.yarnIdentityPreserving[dir]; names != nil {
				if _, ok := names[packageName]; ok {
					return packageName, ""
				}
			}
		}
	}
	return resolveDeclaredIdentity(packages, importer, packageName)
}

func parseYarnDescriptorVersions(
	ctx context.Context,
	data []byte,
	coverage *resolutionCoverageSink,
	limits resolverLimits,
) (yarnDescriptorVersionIndex, yarnLockState) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	maxToken := int(limits.maxLockfileBytes)
	if maxToken < 64*1024 {
		maxToken = 64 * 1024
	}
	scanner.Buffer(make([]byte, 0, 64*1024), maxToken)

	var entries []yarnLockEntry
	var current *yarnLockEntry
	metadataSeen := false
	metadataVersionSeen := false
	metadataVersion := ""
	inMetadata := false
	descriptorCount := 0

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return yarnDescriptorVersionIndex{}, yarnLockUnsupported
		}
		rawLine := scanner.Text()
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !yarnIndented(rawLine) {
			current = nil
			inMetadata = false
			if line == "__metadata:" {
				if metadataSeen {
					coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: yarnLockfileName, Detail: "yarn.lock repeats the __metadata section"})
					return yarnDescriptorVersionIndex{}, yarnLockInvalid
				}
				metadataSeen = true
				inMetadata = true
				continue
			}
			if !strings.HasSuffix(line, ":") {
				continue
			}
			descriptors := yarnLockDescriptors(line)
			if len(descriptors) == 0 {
				continue
			}
			if len(descriptors) > limits.maxTotalBindings-descriptorCount {
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: yarnLockfileName, Detail: "yarn.lock descriptor budget exceeded"})
				return yarnDescriptorVersionIndex{}, yarnLockInvalid
			}
			descriptorCount += len(descriptors)
			if len(entries) >= limits.maxTotalBindings {
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: yarnLockfileName, Detail: "yarn.lock entry budget exceeded"})
				return yarnDescriptorVersionIndex{}, yarnLockInvalid
			}
			entries = append(entries, yarnLockEntry{descriptors: descriptors})
			current = &entries[len(entries)-1]
			continue
		}

		indent, tabIndent := yamlIndent(rawLine)
		if tabIndent {
			coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: yarnLockfileName, Detail: "yarn.lock uses tab indentation in correlated metadata"})
			return yarnDescriptorVersionIndex{}, yarnLockInvalid
		}
		if current == nil {
			if inMetadata && indent == 2 && strings.HasPrefix(line, "version:") {
				if metadataVersionSeen {
					coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: yarnLockfileName, Detail: "yarn.lock __metadata repeats the version field"})
					return yarnDescriptorVersionIndex{}, yarnLockInvalid
				}
				metadataVersionSeen = true
				metadataVersion = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version:")), `"' `)
			}
			continue
		}
		if indent != 2 {
			continue
		}
		switch {
		case strings.HasPrefix(line, "version "):
			if current.versionSeen {
				current.malformed = true
				continue
			}
			current.versionSeen = true
			current.version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version")), `:" `)
		case strings.HasPrefix(line, "version:"):
			if current.versionSeen {
				current.malformed = true
				continue
			}
			current.versionSeen = true
			current.version = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "version:")), `" `)
		case strings.HasPrefix(line, "resolution:"):
			if current.resolutionSeen {
				current.malformed = true
				continue
			}
			current.resolutionSeen = true
			current.resolution = strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "resolution:")), `" `)
		}
	}
	if err := scanner.Err(); err != nil {
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMetadataBudgetExceeded, Path: yarnLockfileName, Detail: "yarn.lock contains a line beyond the parser budget"})
		return yarnDescriptorVersionIndex{}, yarnLockInvalid
	}
	if !metadataSeen {
		coverage.add(jsresolution.CoverageIssue{
			Kind:   jsresolution.CoverageUnsupportedPackageManager,
			Path:   yarnLockfileName,
			Detail: "only Yarn Berry lockfiles with __metadata version 8 or 10 are supported for importer selection",
		})
		return yarnDescriptorVersionIndex{}, yarnLockUnsupported
	}
	if !metadataVersionSeen {
		coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: yarnLockfileName, Detail: "yarn.lock __metadata has no version field"})
		return yarnDescriptorVersionIndex{}, yarnLockInvalid
	}
	if metadataVersion != "8" && metadataVersion != "10" {
		coverage.add(jsresolution.CoverageIssue{
			Kind:   jsresolution.CoverageUnsupportedMetadata,
			Path:   yarnLockfileName,
			Detail: fmt.Sprintf("yarn.lock metadata version %q is outside supported versions 8 and 10", boundedYarnText(metadataVersion)),
		})
		return yarnDescriptorVersionIndex{}, yarnLockInvalid
	}

	out := yarnDescriptorVersionIndex{versions: map[string][]string{}, invalid: map[string]struct{}{}}
	descriptorSeen := map[string]struct{}{}
	for _, entry := range entries {
		version := strings.TrimSpace(entry.version)
		for _, descriptor := range entry.descriptors {
			if strings.Contains(descriptor, "@workspace:") {
				continue
			}
			name := yarnLockSpecName(descriptor)
			if name == "" {
				continue
			}
			request := strings.TrimPrefix(descriptor, name+"@")
			if !yarnRequestIsNPMRegistry(name, request) {
				continue
			}
			if _, duplicate := descriptorSeen[descriptor]; duplicate {
				out.invalid[descriptor] = struct{}{}
				coverage.add(jsresolution.CoverageIssue{
					Kind:   jsresolution.CoverageUnsupportedMetadata,
					Path:   yarnLockfileName,
					Detail: fmt.Sprintf("yarn.lock repeats descriptor %q in multiple entries", boundedYarnText(descriptor)),
				})
				continue
			}
			descriptorSeen[descriptor] = struct{}{}
			if entry.malformed {
				out.invalid[descriptor] = struct{}{}
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: yarnLockfileName, Detail: fmt.Sprintf("yarn.lock descriptor %q repeats a correlated field", boundedYarnText(descriptor))})
				continue
			}
			if !entry.versionSeen || !sbom.IsResolvedVersion(version) {
				out.invalid[descriptor] = struct{}{}
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: yarnLockfileName, Detail: fmt.Sprintf("yarn.lock descriptor %q has no resolved version", boundedYarnText(descriptor))})
				continue
			}
			if !entry.resolutionSeen || entry.resolution == "" {
				out.invalid[descriptor] = struct{}{}
				coverage.add(jsresolution.CoverageIssue{Kind: jsresolution.CoverageMalformedMetadata, Path: yarnLockfileName, Detail: fmt.Sprintf("yarn.lock descriptor %q has no resolution locator", boundedYarnText(descriptor))})
				continue
			}
			{
				resolvedName, resolvedVersion, ok := yarnNPMResolutionIdentity(entry.resolution)
				if !ok || resolvedName != name || resolvedVersion != version {
					out.invalid[descriptor] = struct{}{}
					coverage.add(jsresolution.CoverageIssue{
						Kind:   jsresolution.CoverageUnsupportedMetadata,
						Path:   yarnLockfileName,
						Detail: fmt.Sprintf("yarn.lock descriptor %q has inconsistent resolution locator %q for version %q", boundedYarnText(descriptor), boundedYarnText(entry.resolution), boundedYarnText(version)),
					})
					continue
				}
			}
			out.versions[descriptor] = append(out.versions[descriptor], version)
		}
	}
	for descriptor := range out.versions {
		sort.Strings(out.versions[descriptor])
		out.versions[descriptor] = deduplicateStrings(out.versions[descriptor])
	}
	return out, yarnLockSupported
}

func yarnNPMResolutionIdentity(value string) (string, string, bool) {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	separator := strings.Index(value, "@npm:")
	if separator <= 0 {
		return "", "", false
	}
	name, err := jsresolution.NormalizePackageName(value[:separator])
	if err != nil {
		return "", "", false
	}
	version := value[separator+len("@npm:"):]
	if index := strings.Index(version, "::"); index >= 0 {
		version = version[:index]
	}
	version = strings.TrimSpace(version)
	if !sbom.IsResolvedVersion(version) {
		return "", "", false
	}
	return name, version, true
}

func yarnLockDescriptors(keyLine string) []string {
	key := strings.TrimSuffix(strings.TrimSpace(keyLine), ":")
	var out []string
	for _, part := range strings.Split(key, ",") {
		descriptor := strings.Trim(strings.TrimSpace(part), `"`)
		if descriptor != "" && yarnLockSpecName(descriptor) != "" {
			out = append(out, descriptor)
		}
	}
	sort.Strings(out)
	return deduplicateStrings(out)
}

func yarnLockSpecName(spec string) string {
	for i := 1; i < len(spec); i++ {
		if spec[i] == '@' {
			return spec[:i]
		}
	}
	return ""
}

func yarnResolvedVersions(index yarnDescriptorVersionIndex, name, request string) ([]string, bool) {
	keys := []string{name + "@" + request}
	if !strings.HasPrefix(request, "npm:") {
		keys = append(keys, name+"@npm:"+request)
	}
	var out []string
	invalid := false
	for _, key := range keys {
		if _, bad := index.invalid[key]; bad {
			invalid = true
		}
		out = append(out, index.versions[key]...)
	}
	sort.Strings(out)
	return deduplicateStrings(out), invalid
}

func yarnRequestIsNPMRegistry(name, request string) bool {
	request = strings.TrimSpace(request)
	if request == "" || strings.HasPrefix(request, "workspace:") {
		return false
	}
	if strings.HasPrefix(request, "npm:") {
		target := strings.TrimSpace(strings.TrimPrefix(request, "npm:"))
		if target == "" {
			return false
		}
		if sbom.IsResolvedVersion(target) {
			return true
		}
		if targetName := yarnAliasTargetName(target); targetName != "" {
			normalized, err := jsresolution.NormalizePackageName(targetName)
			return err == nil && normalized == name
		}
		return true
	}
	if strings.Contains(request, ":") || strings.Contains(request, "/") || strings.HasPrefix(request, ".") {
		return false
	}
	return true
}

func yarnNPMProtocolKeepsIdentity(name, request string) bool {
	request = strings.TrimSpace(request)
	if !strings.HasPrefix(request, "npm:") {
		return false
	}
	target := strings.TrimSpace(strings.TrimPrefix(request, "npm:"))
	if target == "" {
		return false
	}
	if sbom.IsResolvedVersion(target) {
		return true
	}
	targetName := yarnAliasTargetName(target)
	if targetName == "" {
		return true
	}
	normalized, err := jsresolution.NormalizePackageName(targetName)
	return err == nil && normalized == name
}

func yarnAliasTargetName(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if normalized, err := jsresolution.NormalizePackageName(target); err == nil {
		return normalized
	}
	if target[0] == '@' {
		for i := 1; i < len(target); i++ {
			if target[i] == '@' {
				return target[:i]
			}
		}
		return ""
	}
	if at := strings.IndexByte(target, '@'); at > 0 {
		return target[:at]
	}
	return ""
}

func yarnIndented(raw string) bool {
	return strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
}

func boundedYarnText(value string) string {
	const max = 160
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
