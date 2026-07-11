package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func hasPURL(comps []sbom.Component, purl string) bool {
	for _, c := range comps {
		if c.PURL == purl {
			return true
		}
	}
	return false
}

// completeScopes=true (Maven: `dependency:list` enumerates all non-test scopes) must replace syft's ENTIRE
// pkg:maven view with the resolved tree – not just the unversioned pom placeholders. Regression guard for
// the "built target/ inflation" bug: scanning an already-built Spring Boot project makes syft catalog every
// dependency a second time as a concretely-versioned nested BOOT-INF/lib jar, which the old
// (drop-only-unversioned) merge kept, inflating the component count + emitting UNKNOWN-license noise.
func TestMergeResolvedJVMMavenDropsBuiltJars(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		// syft's unversioned pom placeholder (old code already dropped this)
		{Name: "org.springframework.boot:spring-boot-starter-web", Version: "", PURL: "pkg:maven/org.springframework.boot/spring-boot-starter-web"},
		// syft's CONCRETELY-VERSIONED jar cataloged from target/ (a fat-jar nested jar) – the leak.
		{Name: "org.apache.commons:commons-lang3", Version: "3.10", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.10", Scope: sbom.ScopeProduction},
		// a non-JVM component in the same repo must survive.
		{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Scope: sbom.ScopeProduction},
	}}
	resolved := []sbom.Component{
		{Name: "org.springframework.boot:spring-boot-starter-web", Version: "2.3.4.RELEASE", PURL: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.3.4.RELEASE", Scope: sbom.ScopeProduction},
		{Name: "org.apache.commons:commons-lang3", Version: "3.10", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.10", Scope: sbom.ScopeProduction},
	}

	mergeResolvedJVM(doc, resolved, true)

	// Result = resolved JVM tree (2) + the non-JVM survivor (1). No leftover syft pkg:maven duplicates.
	if got := len(doc.Components); got != 3 {
		t.Fatalf("component count = %d, want 3 (2 resolved + 1 npm): %+v", got, doc.Components)
	}
	if !hasPURL(doc.Components, "pkg:npm/lodash@4.17.21") {
		t.Error("non-JVM component (npm) must be preserved")
	}
	if !hasPURL(doc.Components, "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.3.4.RELEASE") {
		t.Error("resolved starter (versioned) must be present")
	}
	// The versionless placeholder AND any raw target/-jar pkg:maven must be gone – only resolved coords remain.
	for _, c := range doc.Components {
		if c.PURL == "pkg:maven/org.springframework.boot/spring-boot-starter-web" {
			t.Error("unversioned pom placeholder must be dropped in favor of the resolved version")
		}
	}
}

// completeScopes=false (Gradle: only runtimeClasspath is resolved) must NOT drop a concretely-versioned
// syft pkg:maven jar the resolved tree never listed – those are the provided/compileOnly deps syft
// cataloged from a built build/ dir, and development scope is actionable (not background). Dropping them
// would be a silent coverage gap. Only the unversioned placeholder is superseded.
func TestMergeResolvedJVMGradleKeepsProvidedJars(t *testing.T) {
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "org.springframework.boot:spring-boot-starter-web", Version: "", PURL: "pkg:maven/org.springframework.boot/spring-boot-starter-web"},
		// provided/compileOnly jar syft saw in build/ that runtimeClasspath omits – MUST survive.
		{Name: "javax.servlet:javax.servlet-api", Version: "4.0.1", PURL: "pkg:maven/javax.servlet/javax.servlet-api@4.0.1", Scope: sbom.ScopeDevelopment},
	}}
	resolved := []sbom.Component{
		{Name: "org.springframework.boot:spring-boot-starter-web", Version: "2.3.4.RELEASE", PURL: "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.3.4.RELEASE", Scope: sbom.ScopeProduction},
	}

	mergeResolvedJVM(doc, resolved, false)

	if !hasPURL(doc.Components, "pkg:maven/javax.servlet/javax.servlet-api@4.0.1") {
		t.Error("provided/compileOnly jar not in the runtimeClasspath tree must be kept (no silent gap)")
	}
	if !hasPURL(doc.Components, "pkg:maven/org.springframework.boot/spring-boot-starter-web@2.3.4.RELEASE") {
		t.Error("resolved starter must be present")
	}
	// The unversioned placeholder is still superseded by the resolved version.
	for _, c := range doc.Components {
		if c.PURL == "pkg:maven/org.springframework.boot/spring-boot-starter-web" {
			t.Error("unversioned placeholder must be dropped even on the Gradle path")
		}
	}
}

// With an empty resolved set (resolver did not run / not a JVM project) the merge is a no-op: syft's view
// – including target/ jars, which are then the ONLY version source – must be left intact, never zeroed.
func TestMergeResolvedJVMEmptyResolvedIsNoOp(t *testing.T) {
	orig := []sbom.Component{
		{Name: "org.apache.commons:commons-lang3", Version: "3.10", PURL: "pkg:maven/org.apache.commons/commons-lang3@3.10"},
	}
	doc := &sbom.SBOM{Components: append([]sbom.Component(nil), orig...)}
	mergeResolvedJVM(doc, nil, true)
	if len(doc.Components) != 1 || !hasPURL(doc.Components, "pkg:maven/org.apache.commons/commons-lang3@3.10") {
		t.Fatalf("empty resolved set must leave syft's pkg:maven intact, got %+v", doc.Components)
	}
}
