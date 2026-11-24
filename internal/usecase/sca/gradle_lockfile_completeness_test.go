package sca

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/scanrun"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/acquire"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/tools/ownsbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const gradleLockHeader = "# This is a Gradle generated file for dependency locking.\n" +
	"# Manual edits can break the build and are not advised.\n" +
	"# This file is expected to be part of source control.\n"

// scanWithRealInventory runs a whole scan over dir with the real local acquirer and the real owned SBOM
// producer, so what is asserted is what a CLI scan reports: the workspace's recognised lockfiles (the
// acquirer's view) joined to what the producer actually read (the registry's view). Only detection is faked.
func scanWithRealInventory(t *testing.T, files map[string]string) *ScanResult {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := ownsbom.DefaultRegistry()
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(&fakeEngRepo{eng: engagementWithScope(t, dir)}, nil, nil, nil, nil, nil, nil, nil,
		ports.Provenance{}, fakeClock{t: time.Unix(0, 0).UTC()}, &fakeAudit{}, shared.SeverityHigh, 0,
		acquire.New(), &fakeDetector{}, registry, []ports.DetectionSource{fakeVuln{}}, nil, fakeLic{}, nil)
	result, err := svc.Scan(context.Background(), "operator", "e1", ports.AcquireRequest{Kind: ports.TargetLocal, Value: dir})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	return result
}

// A gradle.lockfile is a resolving source only because the producer reads it. Before it was parsed, a
// directory holding nothing else reported zero components while confident=true and the inventory engine
// complete, which a CI gate (--require-complete) accepted as a clean, fully resolved scan.
func TestGradleLockfileCompletenessFollowsWhatWasRead(t *testing.T) {
	tests := []struct {
		name          string
		lockfile      string
		wantTotal     int
		wantConfident bool
		wantInventory scanrun.CoverageStatus
	}{
		{
			name: "read lockfile with entries is confident and counted",
			lockfile: gradleLockHeader +
				"com.google.guava:guava:31.0-jre=compileClasspath,runtimeClasspath\n" +
				"org.slf4j:slf4j-api:1.7.30=compileClasspath,runtimeClasspath\n" +
				"junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\n" +
				"empty=annotationProcessor,testAnnotationProcessor\n",
			wantTotal:     3,
			wantConfident: true,
			wantInventory: scanrun.CoverageComplete,
		},
		{
			// Parsed and legitimately empty: Gradle wrote the file, the project simply locks nothing.
			name:          "read lockfile with only an empty line is still complete",
			lockfile:      gradleLockHeader + "empty=annotationProcessor,compileClasspath,runtimeClasspath\n",
			wantTotal:     0,
			wantConfident: true,
			wantInventory: scanrun.CoverageComplete,
		},
		{
			// Present but not readable as a lockfile: nothing was read, so nothing may be called complete.
			name:          "present but unreadable lockfile is not complete",
			lockfile:      "this is not a gradle lockfile\n\x00\x01\x02 binary noise\n",
			wantTotal:     0,
			wantConfident: false,
			wantInventory: scanrun.CoverageUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanWithRealInventory(t, map[string]string{"gradle.lockfile": tt.lockfile})
			c := result.Completeness
			if c.ComponentsTotal != tt.wantTotal {
				t.Errorf("components_total = %d, want %d (completeness %+v)", c.ComponentsTotal, tt.wantTotal, c)
			}
			if c.Confident != tt.wantConfident {
				t.Errorf("confident = %v, want %v (completeness %+v)", c.Confident, tt.wantConfident, c)
			}
			outcome, ok := result.engineOutcome("inventory")
			if !ok {
				t.Fatal("no inventory engine outcome recorded")
			}
			complete := outcome.Coverage == scanrun.CoverageComplete
			if complete != (tt.wantInventory == scanrun.CoverageComplete) {
				t.Errorf("inventory coverage = %q, want complete=%v", outcome.Coverage, tt.wantInventory == scanrun.CoverageComplete)
			}
			if !tt.wantConfident && !strings.Contains(c.Warning, "SBOM generation did not run") {
				t.Errorf("an unread lockfile must say why the scan is incomplete, warning = %q", c.Warning)
			}
		})
	}
}

// The build script names only the direct dependencies, and its own warning tells the user to generate a
// lockfile. Following that advice must bring the transitive tree in, not leave the scan confident over the
// direct set alone, and a module both files name must be one component, not two.
func TestGradleBuildScriptWithLockfileReportsTheLockedTree(t *testing.T) {
	result := scanWithRealInventory(t, map[string]string{
		"build.gradle": "dependencies {\n    implementation 'com.google.guava:guava:31.0-jre'\n}\n",
		"gradle.lockfile": gradleLockHeader +
			"com.google.guava:guava:31.0-jre=compileClasspath,runtimeClasspath\n" +
			"com.google.guava:failureaccess:1.0.1=compileClasspath,runtimeClasspath\n" +
			"empty=annotationProcessor\n",
	})
	c := result.Completeness
	if c.ComponentsTotal != 2 {
		t.Errorf("components_total = %d, want 2 (guava once, plus the transitive failureaccess): %+v", c.ComponentsTotal, c)
	}
	if !c.Confident {
		t.Errorf("a build script with the lockfile read beside it is resolved: %+v", c)
	}
}
