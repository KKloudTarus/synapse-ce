package findinglineage

import (
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNormalizeSourceRepoPathRejectsURLsBeforeCleaning(t *testing.T) {
	for _, input := range []string{
		"https://user:private-test-marker@example.test/ci.yaml",
		"http://example.test/ci.yaml",
		"ssh://git@example.test/repo/config.yaml",
		"file:///private/config.yaml",
		"custom://example.test/config.yaml",
	} {
		t.Run(strings.SplitN(input, ":", 2)[0], func(t *testing.T) {
			got, err := normalizeSourceRepoPath("IaC", input)
			if !errors.Is(err, shared.ErrValidation) || got != "" {
				t.Fatalf("URL accepted as a repository path: got=%q err=%v", got, err)
			}
			if strings.Contains(err.Error(), input) || strings.Contains(err.Error(), "private-test-marker") {
				t.Fatal("validation error exposed the rejected locator")
			}
		})
	}
}

func TestNormalizeSourceRepoPathPreservesRelativePathNormalization(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{" ./infra//main.tf ", "infra/main.tf"},
		{"src/Cafe\u0301.yaml", "src/Café.yaml"},
		{".github/workflows/CI.yaml", ".github/workflows/CI.yaml"},
		{"infra/a:b.yaml", "infra/a:b.yaml"},
	} {
		t.Run(test.want, func(t *testing.T) {
			got, err := normalizeSourceRepoPath("IaC", test.input)
			if err != nil || got != test.want {
				t.Fatalf("relative path normalization changed: got=%q want=%q err=%v", got, test.want, err)
			}
		})
	}
}
