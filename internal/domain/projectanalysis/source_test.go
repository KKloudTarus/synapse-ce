package projectanalysis

import (
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/finding"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestSourceCapabilitiesValidate(t *testing.T) {
	unavailable := func(reason UnavailableReason) SourceCapabilities {
		return SourceCapabilities{
			Source: Capability{Reason: reason}, Comparison: Capability{Reason: reason},
			UnifiedDiff: Capability{Reason: reason}, SplitDiff: Capability{Reason: reason}, Highlighting: Capability{Reason: reason},
		}
	}
	cases := []struct {
		name string
		in   SourceCapabilities
		want error
	}{
		{"source only", func() SourceCapabilities {
			c := unavailable(UnavailableFirstAnalysis)
			c.Source = Capability{Available: true}
			return c
		}(), nil},
		{"unavailable with reason", unavailable(UnavailableNotRetained), nil},
		{"unavailable without reason", SourceCapabilities{Source: Capability{}}, ErrCapabilityReason},
		{"available with reason", func() SourceCapabilities {
			c := unavailable(UnavailableNotRetained)
			c.Source = Capability{Available: true, Reason: UnavailableNotRetained}
			return c
		}(), ErrCapabilityReason},
		{"invalid reason", func() SourceCapabilities {
			c := unavailable(UnavailableNotRetained)
			c.Source = Capability{Reason: "unknown"}
			return c
		}(), ErrCapabilityReason},
		{"comparison unavailable", func() SourceCapabilities {
			c := unavailable(UnavailableFirstAnalysis)
			c.Source = Capability{Available: true}
			return c
		}(), nil},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAnnotationValidate(t *testing.T) {
	annotation := Annotation{
		FindingKey: "finding", Kind: finding.KindSAST, Severity: shared.SeverityHigh, Status: finding.StatusOpen,
		Location: finding.SourceLocation{File: "main.go", StartLine: 1, EndLine: 1},
	}
	if err := annotation.Validate(); err != nil {
		t.Fatal(err)
	}
	annotation.Location.File = "../main.go"
	if err := annotation.Validate(); err == nil {
		t.Fatal("invalid source annotation accepted")
	}
}

func TestFileChangeValidate(t *testing.T) {
	cases := []struct {
		name string
		in   FileChange
		want error
	}{
		{"added", FileChange{Status: FileStatusAdded, NewPath: "main.go"}, nil},
		{"deleted", FileChange{Status: FileStatusDeleted, OldPath: "main.go"}, nil},
		{"renamed", FileChange{Status: FileStatusRenamed, OldPath: "old.go", NewPath: "new.go"}, nil},
		{"binary", FileChange{Status: FileStatusModified, OldPath: "main.go", NewPath: "main.go", Binary: true}, nil},
		{"missing status", FileChange{NewPath: "main.go"}, ErrFileChangeStatus},
		{"added old path", FileChange{Status: FileStatusAdded, OldPath: "old.go", NewPath: "main.go"}, ErrFileChangePaths},
		{"deleted new path", FileChange{Status: FileStatusDeleted, OldPath: "old.go", NewPath: "main.go"}, ErrFileChangePaths},
		{"invalid path", FileChange{Status: FileStatusModified, OldPath: "../old.go", NewPath: "new.go"}, ErrFileChangePaths},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.Validate()
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.want)
			}
		})
	}
}
