package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestValidatePublishedCaptureRejectsZeroRetainedSource(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files []projectanalysis.SourceFile
	}{
		{name: "empty manifest"},
		{name: "unavailable only", files: []projectanalysis.SourceFile{{Path: "main.go", Bytes: 13, Reason: projectanalysis.UnavailableLimitExceeded}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			writer := projectanalysis.SourceWriter{Actor: "ci-bot", ToolVersion: "synapse-cli/test", PublishedAt: time.Unix(1_700_000_000, 0).UTC()}
			manifest := projectanalysis.SourceManifest{Writer: &writer, Files: tc.files}
			manifest.SetArtifactDigest()
			capture := projectanalysis.SourceCapture{
				Capabilities: projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
				Manifest:     manifest,
			}
			if err := validatePublishedCapture(capture); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("validatePublishedCapture() error=%v, want validation", err)
			}
		})
	}
}
