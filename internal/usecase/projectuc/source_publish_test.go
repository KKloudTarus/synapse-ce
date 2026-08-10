package projectuc

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/measure"
	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/projectanalysis"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/sourceartifact"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func sourcePublishTestClock() fixedClock {
	return fixedClock{now: time.Date(2026, 8, 10, 2, 0, 0, 0, time.UTC)}
}

type sourceAuditAnalysisStore struct {
	*memory.ProjectAnalysisStore
	mu      sync.Mutex
	sources map[string]projectanalysis.SourceCapture
	audits  []ports.AuditEntry
}

func sourceAttachmentKey(tenantID, projectID, analysisID shared.ID) string {
	return tenantID.String() + "\x00" + projectID.String() + "\x00" + analysisID.String()
}

func (s *sourceAuditAnalysisStore) AttachSourceWithAudit(ctx context.Context, tenantID, projectID, analysisID shared.ID, capture projectanalysis.SourceCapture, audit ports.AuditEntry) error {
	writer := capture.Manifest.Writer
	if writer == nil || audit.Actor != writer.Actor || !audit.At.Equal(writer.PublishedAt) || audit.Action != ports.ProjectSourcePublishAuditAction || audit.Target != analysisID.String() || audit.Metadata["artifact_digest"] != capture.Manifest.Digest || audit.Metadata["tool_version"] != writer.ToolVersion {
		return shared.ErrValidation
	}
	analysis, err := s.ProjectAnalysisStore.Get(ctx, tenantID, projectID, analysisID)
	if err != nil {
		return err
	}
	if analysis.Capabilities.Source.Available || analysis.SourceManifest.Digest != "" {
		return shared.ErrConflict
	}
	key := sourceAttachmentKey(tenantID, projectID, analysisID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sources == nil {
		s.sources = make(map[string]projectanalysis.SourceCapture)
	}
	if _, exists := s.sources[key]; exists {
		return shared.ErrConflict
	}
	s.sources[key] = capture
	s.audits = append(s.audits, audit)
	return nil
}

func (s *sourceAuditAnalysisStore) Get(ctx context.Context, tenantID, projectID, analysisID shared.ID) (projectanalysis.Analysis, error) {
	analysis, err := s.ProjectAnalysisStore.Get(ctx, tenantID, projectID, analysisID)
	if err != nil {
		return projectanalysis.Analysis{}, err
	}
	key := sourceAttachmentKey(tenantID, projectID, analysisID)
	s.mu.Lock()
	capture, ok := s.sources[key]
	s.mu.Unlock()
	if ok {
		analysis.SourceManifest = capture.Manifest
		analysis.Capabilities.Source = projectanalysis.Capability{Available: true}
		analysis.Capabilities.Highlighting = projectanalysis.Capability{Available: true}
	}
	return analysis, nil
}

func sourceTar(t *testing.T, files map[string]string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		data := []byte(body)
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestPublishSourceIsServedThroughReadCodeFileAndExcludesSecrets(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := &sourceAuditAnalysisStore{ProjectAnalysisStore: memory.NewProjectAnalysisStore()}
	artifacts := sourceartifact.New(t.TempDir(), 0, 0, 0)
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)

	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID:             "analysis",
		TenantID:       p.TenantID.String(),
		ProjectID:      p.ID.String(),
		ProjectKey:     p.Key,
		SourceRevision: projectanalysis.SourceRevision{Kind: projectanalysis.ScanKindLocal, Head: "workspace"},
		Capabilities: projectanalysis.SourceCapabilities{
			Source:       projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
			Comparison:   projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			UnifiedDiff:  projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			SplitDiff:    projectanalysis.Capability{Reason: projectanalysis.UnavailableNoComparableBase},
			Highlighting: projectanalysis.Capability{Reason: projectanalysis.UnavailableNotRetained},
		},
		Snapshot: measure.Snapshot{Nodes: []measure.Node{
			{Path: "", Kind: measure.NodeProject},
			{Path: "src/main.go", Kind: measure.NodeFile, Language: "Go"},
			// These deliberately model scanner-inventory drift: durable publication must still deny them.
			{Path: ".env", Kind: measure.NodeFile},
			{Path: "deploy/private.pem", Kind: measure.NodeFile},
		}},
	}
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}

	manifest, err := svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "ci-bot", ToolVersion: "synapse-cli/test", Archive: sourceTar(t, map[string]string{
			"src/main.go":        "package main\n\nfunc main() {}\n",
			".env":               "fixture-blocked-by-path\n",
			"deploy/private.pem": "fixture-blocked-by-path\n",
			"outside.txt":        "not part of scanner inventory\n",
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Writer == nil || manifest.Writer.Actor != "ci-bot" || manifest.Writer.ToolVersion != "synapse-cli/test" || manifest.Digest == "" || manifest.Digest != manifest.ArtifactDigest() {
		t.Fatalf("manifest provenance/digest not sealed: %+v", manifest)
	}
	if len(manifest.Files) != 1 || manifest.Files[0].Path != "src/main.go" || !manifest.Files[0].Available {
		t.Fatalf("unexpected retained files: %+v", manifest.Files)
	}
	if len(analyses.audits) != 1 || analyses.audits[0].Actor != "ci-bot" || analyses.audits[0].Action != ports.ProjectSourcePublishAuditAction || analyses.audits[0].Metadata["artifact_digest"] != manifest.Digest {
		t.Fatalf("audit=%+v", analyses.audits)
	}

	// This is the acceptance test PR #403 lacked: prove the contributed bytes travel through
	// the production project use-case read path, not merely Store.Load.
	view, caps, err := svc.ReadCodeFile(ctx, p.TenantID, p.Key, analysis.ID, "src/main.go", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !caps.Source.Available || view.File.Path != "src/main.go" || len(view.Lines) != 3 || view.Lines[0].Content != "package main" {
		t.Fatalf("view=%+v caps=%+v", view, caps)
	}
	for _, forbidden := range []string{".env", "deploy/private.pem", "outside.txt"} {
		if _, _, err := artifacts.Load(ctx, p.TenantID, p.ID, analysis.ID, forbidden); !errors.Is(err, projectanalysis.ErrSourceNotRetained) {
			t.Fatalf("%s load error=%v, want not retained", forbidden, err)
		}
	}

	if _, err := svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "ci-bot", ToolVersion: "synapse-cli/test", Archive: sourceTar(t, map[string]string{"src/main.go": "replacement\n"}),
	}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate publish error=%v, want conflict", err)
	}
	if len(analyses.audits) != 1 {
		t.Fatalf("duplicate publish emitted audit: %+v", analyses.audits)
	}

	if _, err := svc.PublishSource(ctx, PublishSourceInput{
		TenantID: "other-tenant", ProjectKey: p.Key, AnalysisID: analysis.ID,
		Actor: "mallory", ToolVersion: "synapse-cli/test", Archive: sourceTar(t, map[string]string{"src/main.go": "foreign\n"}),
	}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("foreign-tenant publish error=%v, want not found", err)
	}
}

func TestPublishSourceRejectsUnsupportedAnalysisBeforeArtifactCreation(t *testing.T) {
	ctx := context.Background()
	projects := memory.NewProjectRepository()
	analyses := &sourceAuditAnalysisStore{ProjectAnalysisStore: memory.NewProjectAnalysisStore()}
	artifacts := sourceartifact.New(t.TempDir(), 0, 0, 0)
	svc := NewService(projects, memory.NewEngagementRepository(), sourcePublishTestClock(), fixedIDs{}, &captureAudit{}, true)
	svc.SetAnalysisStore(analyses)
	svc.SetSourceArtifactStore(artifacts)
	p, err := svc.Create(ctx, CreateInput{TenantID: "tenant", CreatedBy: "alice", Name: "Project", Key: "project", SourceBinding: project.SourceBinding{Kind: project.SourceLocal, Value: "/repo"}})
	if err != nil {
		t.Fatal(err)
	}
	analysis := projectanalysis.Analysis{
		ID: "unsupported", TenantID: p.TenantID.String(), ProjectID: p.ID.String(), ProjectKey: p.Key,
		Snapshot: measure.Snapshot{Nodes: []measure.Node{{Path: "", Kind: measure.NodeProject}, {Path: "main.go", Kind: measure.NodeFile}}},
	}
	if err := analyses.Save(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.PublishSource(ctx, PublishSourceInput{
		TenantID: p.TenantID, ProjectKey: p.Key, AnalysisID: analysis.ID, Actor: "ci-bot", ToolVersion: "test", Archive: sourceTar(t, map[string]string{"main.go": "package main\n"}),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unsupported target error=%v, want validation", err)
	}
	if len(analyses.audits) != 0 {
		t.Fatalf("unsupported target emitted audit: %+v", analyses.audits)
	}
}
