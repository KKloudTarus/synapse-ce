package projectuc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/project"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/infrastructure/persistence/memory"
)

// TestCreateRefusesACallerNamedArchivePath pins #1701: an archive source is a path on the server's
// disk, so only the upload path may create one. Before the fix a tenant could bind a project to any
// readable file on the host, including another tenant's stored upload.
func TestCreateRefusesACallerNamedArchivePath(t *testing.T) {
	svc := NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	_, err := svc.Create(context.Background(), CreateInput{
		TenantID: "default", CreatedBy: "op", Name: "Other upload", Key: "other-upload",
		SourceBinding: project.SourceBinding{Kind: project.SourceArchive, Value: "/var/lib/synapse/projects/p-other/src.zip"},
	})
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "uploading the archive") {
		t.Fatalf("err = %v, want the archive binding refused", err)
	}
}

// TestAnalysisRefusesAnArchiveBindingToAnotherProjectsUpload covers bindings stored before #1701,
// when Create accepted any archive path: only this project's own upload may be acquired.
func TestAnalysisRefusesAnArchiveBindingToAnotherProjectsUpload(t *testing.T) {
	svc := NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	cases := []struct {
		value   string
		refused bool
	}{
		{value: "/var/lib/synapse/project-uploads/p-mine.zip"},
		{value: "/var/lib/synapse/project-uploads/p-mine.tar.gz"},
		{value: "/var/lib/synapse/project-uploads/p-other.zip", refused: true},
		{value: "/var/lib/synapse/project-uploads/p-mine.zip.bak", refused: true},
		{value: "/etc/passwd", refused: true},
	}
	for _, tc := range cases {
		p := &project.Project{ID: "p-mine", SourceBinding: project.SourceBinding{Kind: project.SourceArchive, Value: tc.value}}
		_, err := svc.projectAcquireRequest(context.Background(), p)
		if tc.refused != (err != nil) {
			t.Fatalf("binding %q: err = %v, refused want %v", tc.value, err, tc.refused)
		}
		if tc.refused && !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("binding %q refused for the wrong reason: %v", tc.value, err)
		}
	}
}

func TestCreateRefusesAnArchiveKindPaddedWithWhitespace(t *testing.T) {
	svc := NewService(memory.NewProjectRepository(), memory.NewEngagementRepository(), fixedClock{}, fixedIDs{}, &captureAudit{}, true)
	for _, kind := range []string{" archive", "archive ", "\tarchive"} {
		_, err := svc.Create(context.Background(), CreateInput{
			TenantID: "default", CreatedBy: "op", Name: "Padded", Key: "padded",
			SourceBinding: project.SourceBinding{Kind: kind, Value: "/var/lib/synapse/projects/p-other.zip"},
		})
		if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "uploading the archive") {
			t.Fatalf("kind %q: err = %v, want the archive binding refused", kind, err)
		}
	}
}
