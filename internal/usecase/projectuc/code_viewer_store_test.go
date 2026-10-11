package projectuc

import (
	"context"
	"errors"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
)

// A console served by two API replicas reported "source artifact not retained" for an analysis that
// had captured its source, because the artifact directory is pod-local and only the replica that ran
// the analysis holds the bytes. The reason names a retention setting, so an operator reading it looks
// in the wrong place. These two cases pin the distinction the message has to carry.
func TestReadCodeFileSeparatesAMissingStoreFromARetentionDecision(t *testing.T) {
	ctx := context.Background()
	capturedFile := projectanalysis.SourceFile{Path: "main.go", Digest: "digest", Bytes: 13, Lines: 1, Available: true}
	snapshot := measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}}

	t.Run("captured but absent from this server's storage", func(t *testing.T) {
		artifacts := &codeArtifactStub{err: projectanalysis.ErrSourceNotRetained}
		svc, analyses, p := newCodeService(t, artifacts)
		saveCodeAnalysis(t, analyses, p, projectanalysis.Analysis{
			Capabilities:   projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
			SourceManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{capturedFile}},
			Snapshot:       snapshot,
		})
		_, _, err := svc.ReadCodeFile(ctx, p.TenantID, p.Key, "analysis", "main.go", 1, 1)
		if !errors.Is(err, projectanalysis.ErrSourceMissingFromStore) {
			t.Fatalf("error=%v, want the missing-storage reason", err)
		}
		if errors.Is(err, projectanalysis.ErrSourceNotRetained) {
			t.Error("a capture this server cannot find still reads as a retention decision")
		}
	})

	t.Run("never captured", func(t *testing.T) {
		artifacts := &codeArtifactStub{}
		svc, analyses, p := newCodeService(t, artifacts)
		notCaptured := capturedFile
		notCaptured.Available = false
		saveCodeAnalysis(t, analyses, p, projectanalysis.Analysis{
			Capabilities:   projectanalysis.SourceCapabilities{Source: projectanalysis.Capability{Available: true}},
			SourceManifest: projectanalysis.SourceManifest{Files: []projectanalysis.SourceFile{notCaptured}},
			Snapshot:       snapshot,
		})
		_, _, err := svc.ReadCodeFile(ctx, p.TenantID, p.Key, "analysis", "main.go", 1, 1)
		if !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
			t.Fatalf("error=%v, want the retention reason", err)
		}
		if artifacts.loaded {
			t.Error("the store was read for a file the analysis never captured")
		}
	})
}
