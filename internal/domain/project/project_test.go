package project

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestNew(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	profiles := map[string]string{"go": "default"}
	p, err := New("p1", "tenant-a", " Synapse ", "synapse-ce", SourceBinding{Kind: SourceGit, Value: "https://example.com/repo.git", Ref: "main"}, profiles, " gate-1 ", now)
	if err != nil {
		t.Fatal(err)
	}
	profiles["go"] = "changed"
	if p.Name != "Synapse" || p.GateID != "gate-1" || p.DefaultProfileByLang["go"] != "default" || p.Audit.CreatedAt != now {
		t.Fatalf("unexpected project: %+v", p)
	}
}

func TestNewCleansFilesystemSource(t *testing.T) {
	want := filepath.Join(string(filepath.Separator), "repo")
	p, err := New("p1", "tenant-a", "Project", "project", SourceBinding{Kind: SourceLocal, Value: filepath.Join(want, "..", "repo")}, nil, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if p.SourceBinding.Value != want {
		t.Fatalf("source = %q, want %q", p.SourceBinding.Value, want)
	}
}

func TestNewRejectsInvalidInput(t *testing.T) {
	now := time.Now()
	valid := SourceBinding{Kind: SourceLocal, Value: "/repo"}
	cases := []struct {
		name, key string
		id        shared.ID
		source    SourceBinding
	}{
		{"missing id", "ok", "", valid},
		{"missing name", "ok", "p1", valid},
		{"bad key", "Not A Slug", "p1", valid},
		{"missing source", "ok", "p1", SourceBinding{Kind: SourceLocal}},
		{"bad kind", "ok", "p1", SourceBinding{Kind: "image", Value: "x"}},
		{"insecure git", "ok", "p1", SourceBinding{Kind: SourceGit, Value: "http://example.com/repo.git"}},
		{"git without host", "ok", "p1", SourceBinding{Kind: SourceGit, Value: "https://"}},
		{"git with credentials", "ok", "p1", SourceBinding{Kind: SourceGit, Value: "https://user:token@example.com/repo.git"}},
		{"bad git ref", "ok", "p1", SourceBinding{Kind: SourceGit, Value: "https://example.com/repo.git", Ref: "--depth=2"}},
		{"ref on local", "ok", "p1", SourceBinding{Kind: SourceLocal, Value: "/repo", Ref: "main"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "Project"
			if tc.name == "missing name" {
				name = ""
			}
			if _, err := New(tc.id, "", name, tc.key, tc.source, nil, "", now); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("got %v, want validation error", err)
			}
		})
	}
}
