package file

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

func TestAuditLogAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl") // also exercises dir creation
	a := NewAuditLog(path)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		entry := ports.AuditEntry{Actor: "operator", Action: "aup.accept", Target: "aup:1.0", At: time.Unix(int64(i), 0).UTC()}
		if err := a.Record(ctx, entry); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Fatalf("append-only: want 2 lines, got %d (%q)", n, b)
	}
	if !strings.Contains(string(b), `"action":"aup.accept"`) {
		t.Fatalf("audit entry not recorded: %s", b)
	}
}

func TestAuditLogChainsAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx := shared.WithTenant(context.Background(), "tenant-a")

	// First process: write two entries.
	a := NewAuditLog(path)
	for i := 0; i < 2; i++ {
		if err := a.Record(ctx, ports.AuditEntry{Actor: "operator", Action: "x", Target: "t", At: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	// Second process (new AuditLog, same path): the head must be recovered from the
	// file so the chain continues unbroken across a restart.
	a2 := NewAuditLog(path)
	if err := a2.Record(ctx, ports.AuditEntry{Actor: "alice", Action: "y", Target: "t", At: time.Unix(2, 0).UTC()}); err != nil {
		t.Fatalf("record after restart: %v", err)
	}

	rep, err := a2.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.Intact || rep.Verified != 3 || rep.Unchained != 0 {
		t.Fatalf("fresh chain must be intact 3/0, got %+v", rep)
	}

	// List returns newest-first with the chain hashes populated.
	got, err := a2.List(ctx, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 3 || got[0].Action != "y" || got[0].Hash == "" || got[0].PreviousHash == "" {
		t.Fatalf("list must expose chain links newest-first, got %+v", got)
	}
}

func TestAuditLogVerifyDetectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	a := NewAuditLog(path)
	for _, act := range []string{"a", "b", "c"} {
		if err := a.Record(ctx, ports.AuditEntry{Actor: "operator", Action: act, Target: "t", At: time.Unix(0, 0).UTC()}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	// Tamper: rewrite the middle line's action in place (hash now mismatches content).
	raw, _ := os.ReadFile(path)
	tampered := strings.Replace(string(raw), `"action":"b"`, `"action":"HACKED"`, 1)
	if tampered == string(raw) {
		t.Fatal("test setup: nothing was replaced")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	rep, err := NewAuditLog(path).Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.Intact {
		t.Fatalf("tampering must be detected, report = %+v", rep)
	}
}

func TestAuditLogRejectsMalformedRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a := NewAuditLog(path)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := a.Record(ctx, ports.AuditEntry{Actor: "operator", Action: "a", Target: "t", At: time.Unix(int64(i), 0).UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	firstEnd := strings.IndexByte(string(raw), '\n') + 1
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"malformed middle", append(append(append([]byte(nil), raw[:firstEnd]...), []byte("{bad json}\n")...), raw[firstEnd:]...)},
		{"blank record", append(append(append([]byte(nil), raw[:firstEnd]...), '\n'), raw[firstEnd:]...)},
		{"torn final", append(append([]byte(nil), raw...), []byte("{\"actor\":\"partial\"")...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			broken := NewAuditLog(path)
			if _, err := broken.Verify(ctx); err == nil {
				t.Fatal("Verify accepted corrupt audit log")
			}
			if _, err := broken.List(ctx, 10); err == nil {
				t.Fatal("List accepted corrupt audit log")
			}
			if err := broken.RecordOnce(ctx, ports.AuditEntry{Actor: "operator", Action: "a", Target: "t", Metadata: map[string]string{"idempotency_key": "retry"}, At: time.Unix(2, 0).UTC()}); err == nil {
				t.Fatal("RecordOnce wrote through corrupt audit log")
			}
		})
	}
}

func TestAuditLogRecordOnceScopesIdempotencyByTenant(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	log := NewAuditLog(path)
	ctx := context.Background()
	entry := ports.AuditEntry{
		Actor:    "operator",
		Action:   "promotion.apply",
		Target:   "finding-1",
		Metadata: map[string]string{"idempotency_key": "retry"},
		At:       time.Unix(0, 0).UTC(),
	}

	for _, tenantCtx := range []context.Context{
		shared.WithTenant(ctx, "tenant-a"),
		shared.WithTenant(ctx, "tenant-a"),
		shared.WithTenant(ctx, "tenant-b"),
		ctx,
		ctx,
	} {
		if err := log.RecordOnce(tenantCtx, entry); err != nil {
			t.Fatalf("RecordOnce: %v", err)
		}
	}
	if _, ok := entry.Metadata["tenant_id"]; ok {
		t.Fatal("RecordOnce mutated caller metadata")
	}

	entries, err := log.List(shared.WithTenant(ctx, "tenant-a"), 10)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("tenant-a idempotent audit entries = %d, want 1", len(entries))
	}
	for _, e := range entries {
		if _, ok := e.Metadata["tenant_id"]; ok {
			t.Fatal("tenant identity leaked into audit metadata")
		}
	}
	if report, err := log.Verify(shared.WithTenant(ctx, "tenant-a")); err != nil || !report.Intact {
		t.Fatalf("Verify = %+v, %v", report, err)
	}
}

func TestAuditLogTenantEndpointsIsolateV2Chains(t *testing.T) {
	log := NewAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	base := context.Background()
	a := shared.WithTenant(base, "tenant-a")
	b := shared.WithTenant(base, "tenant-b")
	if err := log.Record(a, ports.AuditEntry{Actor: "a", Action: "a1", Target: "t", At: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := log.Record(b, ports.AuditEntry{Actor: "b", Action: "b1", Target: "t", At: time.Unix(2, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := log.Record(a, ports.AuditEntry{Actor: "a", Action: "a2", Target: "t", At: time.Unix(3, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	got, err := log.List(a, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Action != "a2" || got[1].Action != "a1" {
		t.Fatalf("tenant A entries = %#v", got)
	}
	if rep, err := log.Verify(a); err != nil || !rep.Intact || rep.Verified != 2 {
		t.Fatalf("tenant A verify = %+v, %v", rep, err)
	}
	got, err = log.List(b, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Action != "b1" {
		t.Fatalf("tenant B entries = %#v", got)
	}
	if _, err := log.List(base, 10); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant List error = %v", err)
	}
	if _, err := log.Verify(base); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("missing tenant Verify error = %v", err)
	}
}

func TestAuditLogTenantEndpointsHideLegacyEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	legacy := NewAuditLog(path)
	if err := legacy.Record(context.Background(), ports.AuditEntry{Actor: "legacy", Action: "old", Target: "t", At: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	log := NewAuditLog(path)
	ctx := shared.WithTenant(context.Background(), "tenant-a")
	got, err := log.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("tenant endpoint exposed legacy entries: %#v", got)
	}
	if rep, err := log.Verify(ctx); err != nil || !rep.Intact || rep.Verified != 0 {
		t.Fatalf("tenant verify legacy chain = %+v, %v", rep, err)
	}
}
