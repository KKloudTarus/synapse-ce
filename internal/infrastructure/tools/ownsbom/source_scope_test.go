package ownsbom

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestDevPackageScopeIsEncodedOnOutgoingEdges(t *testing.T) {
	t.Run("cargo direct dev root", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte("[dev-dependencies]\ndevroot = \"1\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		lock := []byte(`version = 3

[[package]]
name = "devroot"
version = "1.0.0"
dependencies = ["leaf 1.0.0"]

[[package]]
name = "leaf"
version = "1.0.0"
`)
		_, deps, err := Cargo{}.Parse(context.Background(), ParseInput{Dir: dir, Path: filepath.Join(dir, "Cargo.lock"), Content: lock})
		if err != nil {
			t.Fatal(err)
		}
		leaf := "pkg:cargo/leaf@1.0.0"
		if sbom.ProductionReachable(deps)[leaf] {
			t.Fatalf("dev-root transitive leaf must not be production-reachable: %+v", deps)
		}
	})

	t.Run("poetry dev category", func(t *testing.T) {
		lock := []byte(`[[package]]
name = "devroot"
version = "1.0.0"
category = "dev"
[package.dependencies]
leaf = "1.0.0"

[[package]]
name = "leaf"
version = "1.0.0"
category = "main"
`)
		_, deps, err := Poetry{}.Parse(context.Background(), ParseInput{Path: "poetry.lock", Content: lock})
		if err != nil {
			t.Fatal(err)
		}
		leaf := "pkg:pypi/leaf@1.0.0"
		if sbom.ProductionReachable(deps)[leaf] {
			t.Fatalf("dev-category transitive leaf must not be production-reachable: %+v", deps)
		}
	})
}
