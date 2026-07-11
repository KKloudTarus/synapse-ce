package sca

import (
	"slices"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestIsPinnedVersion(t *testing.T) {
	for _, v := range []string{"4.17.21", "v1.2.3", "0.0.1", "v0.0.0-20220101"} {
		if !isPinnedVersion(v) {
			t.Errorf("%q should be pinned", v)
		}
	}
	for _, v := range []string{"", "^4.0.0", "~1.2", ">=1.0", "*", "latest", "x"} {
		if isPinnedVersion(v) {
			t.Errorf("%q should NOT be pinned", v)
		}
	}
}

func TestComputeCompleteness(t *testing.T) {
	// No lockfile + range versions: must warn and not be confident.
	doc := &sbom.SBOM{Components: []sbom.Component{{Name: "a", Version: "^1.0"}, {Name: "b", Version: "~2"}}}
	c := computeCompleteness(doc, nil, nil)
	if c.Confident || c.Warning == "" {
		t.Errorf("no-lockfile/unresolved should warn + not be confident: %+v", c)
	}
	if c.ComponentsResolved != 0 {
		t.Errorf("resolved=%d, want 0", c.ComponentsResolved)
	}

	// Lockfile + pinned versions: confident, no warning.
	doc2 := &sbom.SBOM{Components: []sbom.Component{{Name: "a", Version: "1.0.0"}, {Name: "b", Version: "2.0.0"}}}
	c2 := computeCompleteness(doc2, []string{"package-lock.json"}, nil)
	if !c2.Confident || c2.Warning != "" {
		t.Errorf("lockfile + pinned should be confident with no warning: %+v", c2)
	}
}

func TestComputeCompletenessOSScan(t *testing.T) {
	// A container/OS scan: installed deb packages, NO manifest lockfile. The OS package DB is
	// the authoritative pinned source, so it must be CONFIDENT with NO "provide a lockfile"
	// warning (the prior misfire), and the os-package-db source recorded.
	osDoc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "curl", Version: "7.52.1-5+deb9u9", PURL: "pkg:deb/debian/curl@7.52.1-5+deb9u9"},
		{Name: "bzip2", Version: "1.0.6-8.1", PURL: "pkg:deb/debian/bzip2@1.0.6-8.1"},
		{Name: "musl", Version: "1.2.2-r0", PURL: "pkg:apk/alpine/musl@1.2.2-r0"},
	}}
	c := computeCompleteness(osDoc, nil, nil)
	if !c.Confident {
		t.Errorf("OS scan with installed packages must be confident, got %+v", c)
	}
	if c.Warning != "" {
		t.Errorf("OS scan must NOT warn 'provide a lockfile', got %q", c.Warning)
	}
	if !slices.Contains(c.Lockfiles, osPackageDB) {
		t.Errorf("OS scan must record the os-package-db source, got lockfiles %v", c.Lockfiles)
	}

	// Mixed image: OS packages + an app build system with NO lockfile (unresolved) – that app
	// gap is still a real INCOMPLETE signal even though the OS side is fine.
	mixed := &sbom.SBOM{Components: []sbom.Component{
		{Name: "curl", Version: "7.52.1", PURL: "pkg:deb/debian/curl@7.52.1"},
	}}
	cm := computeCompleteness(mixed, nil, []string{"maven"})
	if cm.Confident || cm.Warning == "" {
		t.Errorf("an unresolved app build system inside an image must still warn, got %+v", cm)
	}

	// A SOURCE scan (npm, no lockfile, no OS packages) must STILL get the lockfile warning.
	src := &sbom.SBOM{Components: []sbom.Component{{Name: "lodash", Version: "^4.0", PURL: "pkg:npm/lodash"}}}
	cs := computeCompleteness(src, nil, nil)
	if cs.Confident || cs.Warning == "" {
		t.Errorf("a source scan without a lockfile must still warn, got %+v", cs)
	}

	// SECURITY regression: a FEW range-versioned app deps (no lockfile) must NOT hide behind
	// MANY pinned OS packages. Confidence is judged on the app (non-OS) components only, so this
	// stays non-confident + warns – abundant pinned OS packages can't dilute the unresolved app surface.
	mixedApp := &sbom.SBOM{Components: []sbom.Component{
		{Name: "curl", Version: "7.52.1", PURL: "pkg:deb/debian/curl@7.52.1"},   // pinned OS
		{Name: "bash", Version: "4.4-5", PURL: "pkg:deb/debian/bash@4.4-5"},     // pinned OS
		{Name: "openssl", Version: "1.1.0", PURL: "pkg:deb/debian/openssl@1.1"}, // pinned OS
		{Name: "lodash", Version: "^4.0", PURL: "pkg:npm/lodash"},               // UNRESOLVED app dep, no lockfile
	}}
	cma := computeCompleteness(mixedApp, nil, nil)
	if cma.Confident {
		t.Errorf("unresolved app deps must not hide behind pinned OS packages (false-confident), got %+v", cma)
	}
	if cma.Warning == "" {
		t.Errorf("mixed image with unresolved app deps must warn, got %+v", cma)
	}
}

func TestUnresolvedRemediation(t *testing.T) {
	// Maven must NOT be told to write a lockfile (it has none) – it gets build/resolve guidance.
	maven := unresolvedRemediation([]string{"maven"})
	if !strings.Contains(maven, "mvn package") || !strings.Contains(maven, "copy-dependencies") {
		t.Errorf("maven guidance must mention building/resolving, got: %q", maven)
	}
	if strings.Contains(maven, "write-locks") {
		t.Errorf("maven guidance must NOT suggest a lockfile (Maven has none): %q", maven)
	}
	// Gradle keeps the lockfile guidance.
	gradle := unresolvedRemediation([]string{"gradle"})
	if !strings.Contains(gradle, "write-locks") {
		t.Errorf("gradle guidance must mention the lockfile, got: %q", gradle)
	}
	// Both ⇒ both tips present.
	both := unresolvedRemediation([]string{"maven", "gradle"})
	if !strings.Contains(both, "mvn package") || !strings.Contains(both, "write-locks") {
		t.Errorf("combined guidance must cover both, got: %q", both)
	}
	// Unknown/empty ecosystem ⇒ generic fallback, never a misleading tool-specific tip.
	fb := unresolvedRemediation([]string{"sbt"})
	if !strings.Contains(fb, "resolved lockfile or a built artifact") || strings.Contains(fb, "mvn") || strings.Contains(fb, "gradle") {
		t.Errorf("unknown ecosystem must get the generic fallback, got: %q", fb)
	}
}
