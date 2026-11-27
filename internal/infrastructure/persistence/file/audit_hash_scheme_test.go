package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestAuditLogVerifiesLinesWrittenBeforeHashSchemes pins the upgrade path of a JSONL audit file: a
// line written by an older release has no hash_scheme and a legacy hash, a line written now names
// the scheme it was hashed with, and the file verifies end to end.
func TestAuditLogVerifiesLinesWrittenBeforeHashSchemes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ctx := shared.WithTenant(context.Background(), "default")
	at := time.Date(2026, 11, 27, 8, 0, 0, 0, time.UTC)

	old := ports.AuditEntry{Actor: "op", Action: "before", Target: "t", Metadata: map[string]string{"a=b": "c"}, At: at}
	old.Hash = audit.ComputeHash(audit.HashSchemeLegacy, "", old.Actor, old.Action, old.Target, old.Metadata, old.At)
	line, err := json.Marshal(auditFileEntry{AuditEntry: old, TenantID: "default"})
	if err != nil {
		t.Fatalf("encode legacy line: %v", err)
	}
	if strings.Contains(string(line), "hash_scheme") {
		t.Fatalf("a legacy line must not carry hash_scheme: %s", line)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatalf("seed legacy line: %v", err)
	}

	log := NewAuditLog(path)
	if err := log.Record(ctx, ports.AuditEntry{Actor: "op", Action: "after", Target: "t", Metadata: map[string]string{"a": "b=c"}, At: at}); err != nil {
		t.Fatalf("record: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	written := fmt.Sprintf(`"hash_scheme":%d`, audit.CurrentHashScheme)
	if len(lines) != 2 || !strings.Contains(lines[1], written) {
		t.Fatalf("new line does not record its scheme %s: %q", written, lines)
	}

	rep, err := log.Verify(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.Intact || rep.Verified != 2 {
		t.Fatalf("report = %+v, want both lines verified", rep)
	}

	// Relabelling the new line with the other scheme is a tamper.
	relabel := fmt.Sprintf(`"hash_scheme":%d`, audit.HashSchemeFramed+audit.HashSchemeLegacy-audit.CurrentHashScheme)
	tampered := strings.Replace(string(data), written, relabel, 1)
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	rep, err = NewAuditLog(path).Verify(ctx)
	if err != nil {
		t.Fatalf("verify tampered: %v", err)
	}
	if rep.Intact {
		t.Fatal("a line relabelled to the other scheme still verified")
	}
}
