//go:build linux

package egressbroker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileGrantReplayStoreRejectsReplayAfterRestart(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := privateReplayPath(t)
	store, err := newFileGrantReplayStore(path, now, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("grant-1", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("grant-1", now.Add(time.Minute), now); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("same-process replay error = %v, want %v", err, ErrGrantReplay)
	}
	restarted, err := newFileGrantReplayStore(path, now.Add(time.Second), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Consume("grant-1", now.Add(time.Minute), now.Add(time.Second)); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("restart replay error = %v, want %v", err, ErrGrantReplay)
	}
}

func TestFileGrantReplayStoreIgnoresExpiredRecords(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := privateReplayPath(t)
	if err := os.WriteFile(path, []byte(`{"id":"grant-1","expires_at":1799999999}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newFileGrantReplayStore(path, now, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume("grant-1", now.Add(time.Minute), now); err != nil {
		t.Fatalf("consume expired identity: %v", err)
	}
}

func TestFileGrantReplayStoreRejectsMalformedOrInsecureJournal(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for name, content := range map[string]string{
		"malformed":     "not-json\n",
		"unknown field": `{"id":"grant-1","expires_at":1800000060,"extra":true}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := privateReplayPath(t)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := newFileGrantReplayStore(path, now, os.Geteuid()); err == nil {
				t.Fatal("malformed replay journal must fail startup")
			}
		})
	}
	t.Run("insecure mode", func(t *testing.T) {
		path := privateReplayPath(t)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := newFileGrantReplayStore(path, now, os.Geteuid()); err == nil {
			t.Fatal("group/world-readable replay journal must fail startup")
		}
	})
}

func TestFileGrantReplayStoreSyncFailureBurnsGrant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store, err := newFileGrantReplayStore(privateReplayPath(t), now, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	store.syncFile = func(*os.File) error { return errors.New("forced sync failure") }
	if err := store.Consume("grant-1", now.Add(time.Minute), now); err == nil {
		t.Fatal("sync failure must fail closed")
	}
	if err := store.Consume("grant-1", now.Add(time.Minute), now); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("grant after uncertain append = %v, want %v", err, ErrGrantReplay)
	}
}

func privateReplayPath(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "private")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "grant-replays.jsonl")
}
