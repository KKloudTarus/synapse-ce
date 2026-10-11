package scmwebhook

import (
	"context"
	"errors"
	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
	"strings"
	"testing"
)

func TestAuditGitLabChangedUnsignedUUIDDoesNotRescan(t *testing.T) {
	scans := &fakeProjectScanner{}
	receiver := newReceiverForTest(t, &fakeBindingReader{bindings: []integration.Binding{{ProjectID: "p"}}}, scans, nil)
	event := ports.InboundWebhookEvent{Provider: "gitlab", EventType: "Push Hook", EventID: "one", Body: []byte(`{"object_kind":"push","ref":"refs/heads/main","checkout_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`)}
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err != nil {
		t.Fatal(err)
	}
	event.EventID = "two"
	if err := receiver.ReceiveInboundWebhook(context.Background(), gitLabIdentity(), event); err != nil {
		t.Fatal(err)
	}
	if len(scans.calls) != 1 {
		t.Fatalf("same body scanned %d times", len(scans.calls))
	}
}
func TestAuditGitLabRejectsNonGitSHALength(t *testing.T) {
	if err := validateTarget("main", strings.Repeat("a", 41)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("41-byte hash accepted: %v", err)
	}
}
func TestAuditGitLabClosedMergeRequestDoesNotScan(t *testing.T) {
	body := []byte(`{"object_kind":"merge_request","object_attributes":{"iid":17,"action":"close","state":"closed","source_branch":"feature","target_branch":"release","source_project_id":11,"target_project_id":11,"last_commit":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`)
	_, scan, err := parseGitLab("Merge Request Hook", body)
	if err != nil || scan {
		t.Fatalf("closed MR scan=%v err=%v", scan, err)
	}
}
func TestAuditGitLabSignedKindCannotBeOverriddenByHeader(t *testing.T) {
	body := []byte(`{"object_kind":"merge_request","object_attributes":{"iid":17,"source_branch":"feature","last_commit":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}`)
	if _, _, err := parseGitLab("Push Hook", body); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("header/body mismatch accepted: %v", err)
	}
}

func TestAuditGitLabRejectsInvalidRefComponentsBeforeEnqueue(t *testing.T) {
	for _, ref := range []string{"a//b", "a/.hidden", "a/foo.lock/b", "a/"} {
		if err := validateTarget(ref, strings.Repeat("a", 40)); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("invalid ref %q accepted", ref)
		}
	}
}
