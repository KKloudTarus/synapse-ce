package reachbench

import (
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/benchmark"
)

func TestReadFixtureFileReturnsVerifiedOwnedBytes(t *testing.T) {
	specification := fixtureSpecification(t, DefaultReachabilityBenchmark().Fixtures, "go-source-tier2-input")
	file := specification.Files[0]

	contents, err := ReadFixtureFile(file)
	if err != nil {
		t.Fatalf("ReadFixtureFile: %v", err)
	}
	if int64(len(contents)) != file.Size {
		t.Fatalf("size = %d, want %d", len(contents), file.Size)
	}
	if got := benchmark.SHA256Digest(contents); got != file.Digest {
		t.Fatalf("digest = %q, want %q", got, file.Digest)
	}
	if len(contents) == 0 {
		t.Fatal("fixture contents are empty")
	}
	original := contents[0]
	contents[0] ^= 0xff
	reloaded, err := ReadFixtureFile(file)
	if err != nil {
		t.Fatalf("ReadFixtureFile after mutation: %v", err)
	}
	if reloaded[0] != original {
		t.Fatal("ReadFixtureFile returned shared bytes")
	}
}

func TestReadFixtureFileRejectsMismatchedDeclaration(t *testing.T) {
	specification := fixtureSpecification(t, DefaultReachabilityBenchmark().Fixtures, "go-source-tier2-input")
	file := specification.Files[0]

	cases := []struct {
		name  string
		alter func(*FixtureFile)
	}{
		{
			name:  "metadata",
			alter: func(file *FixtureFile) { file.Size++ },
		},
		{
			name:  "path",
			alter: func(file *FixtureFile) { file.Path = "fixtures/golang/unknown.go" },
		},
		{
			name:  "digest",
			alter: func(file *FixtureFile) { file.Digest = "sha256:" + strings.Repeat("0", 64) },
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			mismatched := file
			test.alter(&mismatched)
			if _, err := ReadFixtureFile(mismatched); err == nil {
				t.Fatal("ReadFixtureFile accepted mismatched declaration")
			}
		})
	}
}
