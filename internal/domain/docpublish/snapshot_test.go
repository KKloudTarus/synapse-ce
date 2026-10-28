package docpublish

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
)

func TestSnapshotAndTrashCompletionPreserveManagedIdentityAndRetirement(t *testing.T) {
	at := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	target := Target{IntegrationID: "integration", SourceKind: EngagementReport, SourceRef: "engagement:assessment", Scope: Engagement, ScopeID: "assessment", Container: "workspace"}
	link := Link{ID: "link", TenantID: "tenant", Target: target, RemotePageID: "page-old", RemoteVersion: 2, RemoteRevision: "old", RemoteURL: "https://www.notion.so/page-old", ContentHash: strings.Repeat("a", 64), AccessProfile: DestinationManagedSnapshotProfile, Revision: 3, RestrictionStatus: "verified", RestrictionCheckedAt: &at, RestrictionNextAt: at.Add(time.Hour), RestrictionCheckVersion: 2, CreatedAt: at, UpdatedAt: at}

	snapshot := completedSnapshotIntent(t, target, link, at.Add(time.Minute), "page-new", 4, "new", strings.Repeat("b", 64), 3)
	next, changed, err := snapshot.Complete(&link)
	if err != nil || !changed {
		t.Fatalf("snapshot completion changed=%v err=%v", changed, err)
	}
	if next.ID != link.ID || next.RemotePageID != "page-new" || next.Revision != 4 || next.RestrictionStatus != "" || next.RestrictionCheckedAt != nil || next.RestrictionCheckVersion != 0 {
		t.Fatalf("snapshot did not preserve current-link identity and clear stale observation: %+v", next)
	}

	stale := snapshot
	stale.ExpectedLinkRevision = 3
	if _, _, err := stale.Complete(&next); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale snapshot completed over newer link: %v", err)
	}

	trash := completedRemovalIntent(t, target, next, at.Add(2*time.Minute), Trash, 4)
	retired, changed, err := trash.Complete(&next)
	if err != nil || !changed || retired.RetiredAt == nil || retired.RemovalKind != RemovalTrash || retired.RemotePageID != next.RemotePageID || retired.Revision != 5 {
		t.Fatalf("trash did not retire exact current snapshot: link=%+v changed=%v err=%v", retired, changed, err)
	}
	if _, _, err := snapshot.Complete(&retired); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("snapshot revived retired page: %v", err)
	}
}

func TestManagedSnapshotAndTrashRejectOrdinaryOrDowngradedIdentity(t *testing.T) {
	at := time.Date(2026, 10, 26, 1, 0, 0, 0, time.UTC)
	target := Target{IntegrationID: "integration", SourceKind: EngagementReport, SourceRef: "engagement:assessment", Scope: Engagement, ScopeID: "assessment", Container: "workspace"}
	link := Link{ID: "link", TenantID: "tenant", Target: target, RemotePageID: "page", RemoteVersion: 1, RemoteURL: "https://www.notion.so/page", ContentHash: strings.Repeat("a", 64), AccessProfile: DestinationManagedSnapshotProfile, Revision: 1, CreatedAt: at, UpdatedAt: at}

	for name, mutate := range map[string]func(*Intent){
		"snapshot without managed profile": func(i *Intent) { i.AccessProfile = "" },
		"snapshot without fence":           func(i *Intent) { i.ExpectedLinkRevision = 0 },
		"trash without managed profile":    func(i *Intent) { i.AccessProfile = "" },
		"trash without fence":              func(i *Intent) { i.ExpectedLinkRevision = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			intent := completedSnapshotIntent(t, target, link, at.Add(time.Minute), "page-next", 1, "", strings.Repeat("b", 64), 1)
			if strings.HasPrefix(name, "trash") {
				intent = completedRemovalIntent(t, target, link, at.Add(time.Minute), Trash, 1)
			}
			mutate(&intent)
			if err := intent.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("invalid managed command accepted: %v", err)
			}
		})
	}

	downgraded := completedSnapshotIntent(t, target, link, at.Add(time.Minute), "page-next", 1, "", strings.Repeat("b", 64), 1)
	downgraded.AccessProfile = ""
	if _, _, err := downgraded.Complete(&link); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("managed link accepted ordinary snapshot: %v", err)
	}

	purged := completedRemovalIntent(t, target, link, at.Add(time.Minute), Purge, 0)
	purgedLink, _, err := purged.Complete(&link)
	if err != nil {
		t.Fatal(err)
	}
	revive := completedSnapshotIntent(t, target, purgedLink, at.Add(2*time.Minute), "page-next", 1, "", strings.Repeat("b", 64), purgedLink.Revision)
	if _, _, err = revive.Complete(&purgedLink); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("snapshot revived a purge retirement: %v", err)
	}
}

func completedSnapshotIntent(t *testing.T, target Target, link Link, at time.Time, page string, version int, revision, hash string, expected int) Intent {
	t.Helper()
	return Intent{ID: "snapshot", TenantID: "tenant", Target: target, LinkID: link.ID, ExpectedLinkRevision: expected, Action: Snapshot, RequestKey: "snapshot-request", PayloadDigest: strings.Repeat("c", 64), ContentHash: hash, AccessProfile: DestinationManagedSnapshotProfile, Marker: MarkerFor("snapshot"), State: writeintent.Done, Version: 2, Attempts: 1, RemoteID: page, RemoteVersion: version, RemoteRevision: revision, RemoteURL: "https://www.notion.so/" + page, CreatedAt: at.Add(-time.Minute), UpdatedAt: at}
}

func completedRemovalIntent(t *testing.T, target Target, link Link, at time.Time, action Action, expected int) Intent {
	t.Helper()
	return Intent{ID: "removal", TenantID: "tenant", Target: target, LinkID: link.ID, ExpectedLinkRevision: expected, Action: action, RequestKey: "removal-request", PayloadDigest: strings.Repeat("d", 64), ContentHash: link.ContentHash, AccessProfile: DestinationManagedSnapshotProfile, Marker: MarkerFor("removal"), State: writeintent.Done, Version: 2, Attempts: 1, RemoteID: link.RemotePageID, RemoteVersion: link.RemoteVersion, RemoteRevision: link.RemoteRevision, RemoteURL: link.RemoteURL, CreatedAt: at.Add(-time.Minute), UpdatedAt: at}
}
