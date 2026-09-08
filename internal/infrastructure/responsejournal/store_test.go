package responsejournal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/evidence"
	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	rdom "github.com/KKloudTarus/synapse-ce/internal/domain/response"
	"github.com/KKloudTarus/synapse-ce/internal/domain/responsesaga"
)

func journalEntry(t *testing.T) fleetagent.ResponseExecutionJournalEntry {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	action, err := rdom.NewAction("action-1", rdom.KindStopProcess, "process-1")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := rdom.CanonicalDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(5_000_000, 0).UTC()
	command := fleetagent.ResponseCommand{
		ProtocolVersion: fleetagent.ResponseCommandProtocolVersion, CommandID: "command-1", TenantID: "tenant-1",
		AgentID: "executor-1", AssetID: "asset-1", EngagementID: "eng-1", Action: action,
		ActionDigest: digest, AttemptKey: "../../attempt-1", VerificationChallenge: strings.Repeat("a", 64),
		AuthorizationTarget: engagement.Target{Kind: engagement.TargetDomain, Value: "process-1"},
		Target:              responsesaga.TargetFingerprint{Kind: responsesaga.FingerprintProcess, ProcessAssetID: "asset-1", ProcessEntityID: "process-1"},
		IssuedAt:            now, NotAfter: now.Add(time.Minute), SigningKeyID: evidence.KeyFingerprint(public),
	}
	command.Signature = fleetagent.SignResponseCommand(private, command)
	commandDigest := fleetagent.ResponseCommandDigest(command)
	result := fleetagent.ResponseExecutionResult{
		AttemptKey: command.AttemptKey, CommandDigest: commandDigest, LeaseID: "lease-1", State: fleetagent.ResponseExecutionApplied,
		ObservedRadius: offensivepolicy.RadiusStateChanging, AffectedCount: 1, CompletedAt: now.Add(time.Second),
	}
	return fleetagent.ResponseExecutionJournalEntry{
		Version: fleetagent.ResponseExecutionJournalVersion, Command: command, CommandDigest: commandDigest,
		LeaseID: "lease-1", LeaseUntil: command.NotAfter, State: result.State, Result: &result,
	}
}

func TestStorePersistsValidatedEntryUnderHashedPath(t *testing.T) {
	root := t.TempDir()
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	entry := journalEntry(t)
	if err := store.SaveResponseExecution(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.LoadResponseExecution(context.Background(), entry.Command.AttemptKey)
	if err != nil || !found || loaded.CommandDigest != entry.CommandDigest || loaded.State != entry.State {
		t.Fatalf("loaded=%+v found=%t err=%v", loaded, found, err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "response-execution"))
	if err != nil || len(entries) != 1 || entries[0].Name() == entry.Command.AttemptKey {
		t.Fatalf("journal files=%v err=%v", entries, err)
	}
	if runtime.GOOS != "windows" {
		info, err := entries[0].Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("journal permissions=%o", info.Mode().Perm())
		}
	}
	listed, err := store.ListResponseExecutions(context.Background())
	if err != nil || len(listed) != 1 || listed[0].CommandDigest != entry.CommandDigest {
		t.Fatalf("listed=%+v err=%v", listed, err)
	}
	if err := store.DeleteResponseExecution(context.Background(), entry.Command.AttemptKey); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.LoadResponseExecution(context.Background(), entry.Command.AttemptKey); err != nil || found {
		t.Fatalf("deleted entry found=%t err=%v", found, err)
	}
}

func TestStorePersistsMonotonicHaltFence(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.RaiseResponseHaltFence(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if err := store.RaiseResponseHaltFence(ctx, 2); err != nil {
		t.Fatal(err)
	}
	generation, halted, err := store.CurrentResponseHaltFence(ctx)
	if err != nil || generation != 3 || !halted {
		t.Fatalf("fence generation=%d halted=%t err=%v", generation, halted, err)
	}
}
