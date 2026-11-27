package engagement

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
)

// TestScopeRefusesALocalRepoTheFloorRefuses pins #1701: an in-scope repo naming a local path the
// operator's floor refuses is rejected when the scope is written, on create and on update, while git
// URLs and out-of-scope entries are not judged by it.
func TestScopeRefusesALocalRepoTheFloorRefuses(t *testing.T) {
	floorErr := errors.New("outside the roots this server allows")
	allowed := abs("srv", "code")
	check := func(path string) error {
		if strings.HasPrefix(path, allowed+string(filepath.Separator)) {
			return nil
		}
		return floorErr
	}
	svc := NewService(newMemRepo(), fixedClock{time.Now()}, fixedIDs{}, &capAudit{})
	svc.SetLocalScopeCheck(check)
	ctx := context.Background()

	cases := []struct {
		name    string
		in, out []domain.Target
		refused bool
	}{
		{name: "local repo under an allowed root", in: []domain.Target{{Kind: domain.TargetRepo, Value: abs("srv", "code", "app")}}},
		{name: "local repo outside", in: []domain.Target{{Kind: domain.TargetRepo, Value: abs("home", "operator")}}, refused: true},
		{name: "git repo is not a local path", in: []domain.Target{{Kind: domain.TargetRepo, Value: "https://github.com/acme/app"}}},
		{name: "out-of-scope local path is not judged", in: []domain.Target{{Kind: domain.TargetRepo, Value: abs("srv", "code", "app")}}, out: []domain.Target{{Kind: domain.TargetRepo, Value: abs("home", "operator")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Create(ctx, CreateInput{TenantID: "default", CreatedBy: "op", Name: "e", Client: "c", InScope: tc.in, OutOfScope: tc.out})
			if tc.refused != (err != nil) {
				t.Fatalf("create err = %v, refused want %v", err, tc.refused)
			}
			if tc.refused && !errors.Is(err, floorErr) {
				t.Fatalf("create refused for the wrong reason: %v", err)
			}
		})
	}

	e, err := svc.Create(ctx, CreateInput{TenantID: "default", CreatedBy: "op", Name: "e", Client: "c", InScope: []domain.Target{{Kind: domain.TargetRepo, Value: abs("srv", "code", "app")}}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.UpdateScope(ctx, "op", "default", e.ID, []domain.Target{{Kind: domain.TargetRepo, Value: abs("opt", "secret")}}, nil); !errors.Is(err, floorErr) {
		t.Fatalf("update err = %v, want the floor's refusal", err)
	}
}

// TestScopeKeepsLocalEntriesItAlreadyHeld covers the upgrade: an engagement scoped before the floor
// existed keeps a local entry outside the roots, stays editable, and its re-test may copy the entry.
func TestScopeKeepsLocalEntriesItAlreadyHeld(t *testing.T) {
	legacy := domain.Target{Kind: domain.TargetRepo, Value: abs("srv", "legacy")}
	svc := NewService(newMemRepo(), fixedClock{time.Now()}, fixedIDs{}, &capAudit{})
	ctx := context.Background()
	// Created before the floor was installed.
	e, err := svc.Create(ctx, CreateInput{TenantID: "default", CreatedBy: "op", Name: "e", Client: "c", InScope: []domain.Target{legacy}})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	refuse := errors.New("outside the roots this server allows")
	svc.SetLocalScopeCheck(func(string) error { return refuse })

	extra := domain.Target{Kind: domain.TargetRepo, Value: "https://github.com/acme/app"}
	if _, err := svc.UpdateScope(ctx, "op", "default", e.ID, []domain.Target{legacy, extra}, nil); err != nil {
		t.Fatalf("editing a scope that keeps its legacy local entry was refused: %v", err)
	}
	added := domain.Target{Kind: domain.TargetRepo, Value: abs("srv", "new")}
	if _, err := svc.UpdateScope(ctx, "op", "default", e.ID, []domain.Target{legacy, added}, nil); !errors.Is(err, refuse) {
		t.Fatalf("a newly added local entry was not judged: %v", err)
	}
	if _, err := svc.Create(ctx, CreateInput{TenantID: "default", CreatedBy: "op", Name: "retest", Client: "c", InScope: []domain.Target{legacy}, InheritedInScope: []domain.Target{legacy}}); err != nil {
		t.Fatalf("a re-test copying the predecessor's local entry was refused: %v", err)
	}
}

// abs builds an absolute path on the current platform's root volume.
func abs(parts ...string) string {
	wd, _ := os.Getwd()
	return filepath.Join(append([]string{filepath.VolumeName(wd) + string(filepath.Separator)}, parts...)...)
}
