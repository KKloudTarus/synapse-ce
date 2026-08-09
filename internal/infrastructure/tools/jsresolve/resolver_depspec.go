package jsresolve

import (
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/jsresolution"
)

// A dependency's declared SPEC decides which package an imported name really refers to. npm-family
// managers support two families that break the "imported name == package name" assumption:
//
//   - an ALIAS ("lodash": "npm:lodash-es@^4.17.21"), where the import resolves to a different package;
//   - a non-registry source (file:, link:, portal:, workspace:, git:, github:, http(s):, patch:), where
//     the installed code is not the registry package of that name at all.
//
// Correlating either to a same-named SBOM component would attach the WRONG identity — and a wrong
// identity that looks deterministic is worse than no identity, because it silently redirects a later
// reachability conclusion onto the wrong package.

// specOutcome is what a declared dependency spec means for identity.
type specOutcome uint8

const (
	// specRegistry is a plain version range: the imported name IS the package name.
	specRegistry specOutcome = iota
	// specAliased redirects the imported name to a different registry package.
	specAliased
	// specForeign installs from somewhere other than the registry, so no component correlation is safe.
	specForeign
)

// nonRegistryProtocols are dependency-spec prefixes that install from outside the npm registry.
var nonRegistryProtocols = []string{
	"file:", "link:", "portal:", "workspace:", "patch:",
	"git:", "git+", "github:", "gitlab:", "bitbucket:",
	"http:", "https:", "ssh:",
}

// classifyDependencySpec interprets a declared dependency spec. For an alias it returns the real
// package name the import resolves to.
func classifyDependencySpec(spec string) (specOutcome, string) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return specRegistry, ""
	}
	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, "npm:") {
		// "npm:name@range" — the alias target is everything before the LAST "@" that follows the name.
		target := strings.TrimSpace(trimmed[len("npm:"):])
		if target == "" {
			return specForeign, ""
		}
		name := target
		if at := strings.LastIndex(target, "@"); at > 0 {
			name = target[:at]
		}
		normalized, err := jsresolution.NormalizePackageName(name)
		if err != nil {
			// An alias whose target is unusable must not fall back to the imported name.
			return specForeign, ""
		}
		return specAliased, normalized
	}

	for _, protocol := range nonRegistryProtocols {
		if strings.HasPrefix(lower, protocol) {
			return specForeign, ""
		}
	}
	// A bare "owner/repo" shorthand is a GitHub dependency, not a version range.
	if !strings.ContainsAny(trimmed, "<>=^~*|") && strings.Count(trimmed, "/") == 1 &&
		!strings.HasPrefix(trimmed, "@") && !startsWithDigit(trimmed) {
		return specForeign, ""
	}
	return specRegistry, ""
}

func startsWithDigit(s string) bool {
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

// declaredSpecFor returns the dependency spec the importer's nearest package.json declares for a
// package name, and whether that package.json declares it at all.
func declaredSpecFor(packages []jsresolution.PackageMetadata, importer, packageName string) (string, bool) {
	owner, ok := packageForRepositoryTarget(packages, importer)
	if !ok {
		return "", false
	}
	for _, dep := range owner.Dependencies {
		if strings.EqualFold(dep.Name, packageName) {
			return dep.Spec, true
		}
	}
	return "", false
}

// resolveDeclaredIdentity applies the declared dependency spec to a package name before correlation. It
// returns the name that should actually be correlated, and a non-empty refusal reason when no
// correlation is safe.
func resolveDeclaredIdentity(packages []jsresolution.PackageMetadata, importer, packageName string) (string, string) {
	spec, declared := declaredSpecFor(packages, importer, packageName)
	if !declared {
		// The nearest package.json does not declare this dependency. That is normal for a transitive or
		// hoisted package, and the imported name is then the package name.
		return packageName, ""
	}
	outcome, target := classifyDependencySpec(spec)
	switch outcome {
	case specAliased:
		return target, ""
	case specForeign:
		return "", "dependency is declared from a non-registry source, so a same-named component is not its identity"
	default:
		return packageName, ""
	}
}
