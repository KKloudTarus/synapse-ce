//go:build linux && amd64

package reachbench

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/toolrunner"
	measurement "github.com/KKloudTarus/synapse-ce/internal/usecase/reachbench"
)

func TestVersionedGoBinaryFixturesBuildWithOfflineMaterializer(t *testing.T) {
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("locate Go toolchain: %v", err)
	}
	input, err := measurement.GoBinaryVersionedBaselineMeasurementInput()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := measurement.ResolveReachabilityProfile(input)
	if err != nil {
		t.Fatal(err)
	}
	materializer, err := NewFixtureMaterializer(FixtureMaterializerDependencies{
		ToolRunner: toolrunner.NewExecRunner(0, 0),
		Platform:   func() string { return "linux/amd64" },
		LocateTool: func(name string) (string, error) {
			if name != "go" {
				return "", fmt.Errorf("unexpected fixture tool %q", name)
			}
			return goPath, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	buildCount := 0
	for _, item := range input.Corpus.Cases {
		if !strings.HasPrefix(item.ID, "go-binary-versioned-") || item.ID == "go-binary-versioned-empty-root-unavailable" {
			continue
		}
		if item.Fixture == nil {
			t.Fatalf("%s has no fixture", item.ID)
		}
		specification, err := profile.ResolveFixtureSpecification(*item.Fixture)
		if err != nil {
			t.Fatal(err)
		}
		if specification.Build == nil {
			t.Fatalf("%s has no build recipe", item.ID)
		}
		t.Run(item.ID, func(t *testing.T) {
			var previousHash [sha256.Size]byte
			for attempt := 0; attempt < 2; attempt++ {
				fixture, err := materializer.Materialize(context.Background(), FixtureMaterializationRequest{
					Specification: specification,
					WorkRoot:      privateMaterializerRoot(t),
					CellKey:       "sha256:" + strings.Repeat("d", 64),
				})
				if err != nil {
					t.Fatalf("build versioned fixture offline (attempt %d): %v", attempt+1, err)
				}
				binaryPath, err := fixture.ResolveOutput(specification.Build.Outputs[0].Path)
				if err != nil {
					t.Fatalf("resolve versioned binary: %v", err)
				}
				binary, err := os.ReadFile(binaryPath)
				if err != nil {
					t.Fatal(err)
				}
				hash := sha256.Sum256(binary)
				if attempt > 0 && hash != previousHash {
					t.Fatal("repeat offline build changed binary bytes")
				}
				previousHash = hash
				metadata, err := exec.Command(goPath, "version", "-m", binaryPath).CombinedOutput()
				if err != nil {
					t.Fatalf("inspect binary module metadata: %v: %s", err, metadata)
				}
				if !strings.Contains(string(metadata), "golang.org/x/net\tv0.59.0") {
					t.Fatalf("versioned dependency absent from binary metadata: %s", metadata)
				}
				if strings.Contains(string(metadata), "=>") {
					t.Fatalf("binary unexpectedly uses a module replacement: %s", metadata)
				}
			}
		})
		buildCount++
	}
	if buildCount != 4 {
		t.Fatalf("built %d Go binary fixtures, want 4", buildCount)
	}
}
