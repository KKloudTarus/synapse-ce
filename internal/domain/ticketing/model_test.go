package ticketing

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
)

func TestLinkRefusesCredentialBearingURLs(t *testing.T) {
	invalid := []string{
		"http://jira.example/browse/SEC-1",
		"https://user:secret@jira.example/browse/SEC-1",
		"https://jira.example/browse/SEC-1?token=secret",
		"https://jira.example/browse/SEC-1#token",
		"https://jira.example/browse/SEC-1?",
		"https://",
		"https://jira.example/browse/SEC-1" + strings.Repeat("a", 2050),
	}
	for _, candidate := range invalid {
		if _, err := CanonicalURL(candidate); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("accepted invalid link: %q", candidate)
		} else if strings.Contains(err.Error(), "secret") {
			t.Fatal("URL validator disclosed a rejected credential")
		}
	}
	if got, err := CanonicalURL(" https://jira.example/browse/SEC-1 "); err != nil || got != "https://jira.example/browse/SEC-1" {
		t.Fatalf("canonicalize URL: %q %v", got, err)
	}
	manual := Link{ID: "link-a", TenantID: "tenant-a", EngagementID: "eng-a", FindingID: "finding-a",
		ExternalURL: "https://jira.example/browse/SEC-1", ExternalID: "SEC-1", CreatedAt: time.Now()}
	if err := manual.Validate(); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("manual link claimed provider ID: %v", err)
	}
	manual.ExternalID = ""
	if err := manual.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMappingRejectsNonPersistableText(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := Mapping{ID: "mapping", TenantID: "tenant", IntegrationID: "integration",
		Scope: Engagement, ScopeID: "engagement", ProjectKey: "SEC", IssueType: "Bug",
		Version: 1, CreatedAt: now, UpdatedAt: now}
	fields := []struct {
		name string
		set  func(*Mapping, string)
	}{
		{"project key", func(m *Mapping, v string) { m.ProjectKey = v }},
		{"issue type", func(m *Mapping, v string) { m.IssueType = v }},
		{"component", func(m *Mapping, v string) { m.Component = v }},
		{"security level", func(m *Mapping, v string) { m.SecurityLevel = v }},
		{"label", func(m *Mapping, v string) { m.Labels = []string{v} }},
		{"priority key", func(m *Mapping, v string) { m.PriorityMap = map[string]string{v: "High"} }},
		{"priority value", func(m *Mapping, v string) { m.PriorityMap = map[string]string{"high": v} }},
	}
	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []string{"text\x00", "text\xff"} {
				mapping := base.Clone()
				field.set(&mapping, value)
				if err := mapping.Validate(); !errors.Is(err, shared.ErrValidation) {
					t.Fatalf("accepted unsupported text %q: %v", value, err)
				}
			}
			mapping := base.Clone()
			field.set(&mapping, "Ưu tiên")
			if err := mapping.Validate(); err != nil {
				t.Fatalf("rejected UTF-8 text: %v", err)
			}
		})
	}
}

func TestIntentApplyRecordsCompletionAndClearsFailureCode(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	intent := testIntent(now)
	lease := now.Add(time.Minute)
	claimed, err := intent.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	lease = lease.Add(time.Hour)
	if claimed.Attempts != 1 || claimed.Version != 2 || claimed.LeaseUntil == nil || !claimed.LeaseUntil.Before(lease) {
		t.Fatalf("claim = %+v", claimed)
	}
	if _, err := claimed.Apply(IntentTransition{Event: writeintent.Acknowledge}, now.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("acknowledged without remote ticket: %v", err)
	}
	done, err := claimed.Apply(IntentTransition{Event: writeintent.Acknowledge, Remote: &RemoteTicket{
		ID: "SEC-1", URL: "https://jira.example/browse/SEC-1",
	}}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if done.State != writeintent.Done || done.RemoteID != "SEC-1" || done.RemoteURL != "https://jira.example/browse/SEC-1" || done.LeaseUntil != nil || done.ErrorCode != "" || done.Version != 3 || done.Attempts != 1 {
		t.Fatalf("done = %+v", done)
	}
	link, err := done.CompletionLink()
	if err != nil {
		t.Fatal(err)
	}
	if link.ID != done.ID || link.TenantID != done.TenantID || link.IntegrationID != done.IntegrationID || link.FindingID != done.FindingID || link.EngagementID != done.EngagementID || link.ExternalID != done.RemoteID || link.ExternalURL != done.RemoteURL || !link.CreatedAt.Equal(done.UpdatedAt) {
		t.Fatalf("completion link = %+v", link)
	}

	claimed, err = intent.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := claimed.Apply(IntentTransition{Event: writeintent.Reject}, now.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("rejected without classification: %v", err)
	}
	failed, err := claimed.Apply(IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	pending, err := failed.Apply(IntentTransition{Event: writeintent.RetryFailed}, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if pending.State != writeintent.Pending || pending.ErrorCode != "" || pending.LeaseUntil != nil || pending.Attempts != 1 || pending.Version != 4 {
		t.Fatalf("retried = %+v", pending)
	}
}

func TestIntentApplyReconcilesMultipleWithoutClaiming(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lease := now.Add(time.Minute)
	claimed, err := testIntent(now).Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	uncertain, err := claimed.Apply(IntentTransition{Event: writeintent.Ambiguous}, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uncertain.Apply(IntentTransition{Event: writeintent.ReconcileMultiple, ErrorCode: "caller_value"}, now.Add(3*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("multiple reconciliation accepted caller code: %v", err)
	}
	multiple, err := uncertain.Apply(IntentTransition{Event: writeintent.ReconcileMultiple}, now.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if multiple.State != writeintent.Uncertain || multiple.ErrorCode != "multiple_matches" || multiple.Attempts != 1 || multiple.Version != 4 {
		t.Fatalf("multiple = %+v", multiple)
	}
	if _, err := multiple.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, now.Add(4*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("claimed multiple-match uncertain intent: %v", err)
	}
	pending, err := multiple.Apply(IntentTransition{Event: writeintent.ReconcileAbsent}, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if pending.ErrorCode != "" || pending.State != writeintent.Pending {
		t.Fatalf("absent reconciliation = %+v", pending)
	}
}

func TestIntentValidationRequiresStateOutcomeFields(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := testIntent(now)
	cases := []struct {
		name string
		edit func(*Intent)
	}{
		{"done missing remote", func(i *Intent) { i.State = writeintent.Done }},
		{"pending has remote", func(i *Intent) { i.RemoteID, i.RemoteURL = "SEC-1", "https://jira.example/browse/SEC-1" }},
		{"failed missing code", func(i *Intent) { i.State = writeintent.Failed }},
		{"uncertain arbitrary code", func(i *Intent) { i.State, i.ErrorCode = writeintent.Uncertain, "provider_rejected" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := base.Clone()
			tc.edit(&intent)
			if err := intent.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("Validate() = %v", err)
			}
		})
	}
}

func TestReconcileLinkPromotesManualLinkWithoutReplacingIdentity(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	existing := Link{ID: "link-a", TenantID: "tenant-a", FindingID: "finding-a", EngagementID: "engagement-a", ExternalURL: "https://jira.example/browse/SEC-1", CreatedAt: now}
	desired := Link{ID: "link-b", TenantID: "tenant-a", FindingID: "finding-a", EngagementID: "engagement-a", IntegrationID: "jira", ExternalID: "SEC-1", ExternalURL: "https://jira.example/browse/SEC-1", CreatedAt: now.Add(time.Second)}
	promoted, err := ReconcileLink(existing, desired)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.ID != existing.ID || !promoted.CreatedAt.Equal(existing.CreatedAt) || promoted.IntegrationID != desired.IntegrationID || promoted.ExternalID != desired.ExternalID {
		t.Fatalf("promoted = %+v", promoted)
	}
	desired.ID, desired.CreatedAt = "link-c", now.Add(2*time.Second)
	reused, err := ReconcileLink(promoted, desired)
	if err != nil || reused.ID != existing.ID || !reused.CreatedAt.Equal(existing.CreatedAt) {
		t.Fatalf("reused = %+v, %v", reused, err)
	}
	desired.ExternalID = "SEC-2"
	if _, err := ReconcileLink(promoted, desired); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("replaced provider identity: %v", err)
	}
	desired.ExternalID = "SEC-1"
	desired.FindingID = "finding-b"
	if _, err := ReconcileLink(promoted, desired); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("reconciled a different finding: %v", err)
	}
}

func testIntent(now time.Time) Intent {
	return Intent{
		ID: "intent-a", TenantID: "tenant-a", IntegrationID: "integration-a", MappingID: "mapping-a",
		FindingID: "finding-a", EngagementID: "engagement-a", Action: Create, RequestKey: "request-a",
		PayloadDigest: strings.Repeat("a", 64), Marker: "synapse-intent-intent-a", State: writeintent.Pending,
		Version: 1, CreatedAt: now, UpdatedAt: now,
	}
}
