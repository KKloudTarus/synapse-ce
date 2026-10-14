package docpublish

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
)

var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func hash(c string) string { return strings.Repeat(c, 64) }

func engagementTarget() Target {
	return Target{IntegrationID: "int-1", SourceKind: EngagementReport, SourceRef: "engagement-report",
		Scope: Engagement, ScopeID: "eng-1", Container: "SEC"}
}

func projectTarget() Target {
	return Target{IntegrationID: "int-1", SourceKind: AssessmentClosureReport, SourceRef: "cycle-1/manifest-1/v2",
		Scope: Project, ScopeID: "proj-1", Container: "SEC"}
}

func pendingIntent(id shared.ID) Intent {
	return Intent{ID: id, TenantID: "tenant-a", Target: engagementTarget(), Action: Create,
		RequestKey: "publish-" + id.String(), PayloadDigest: hash("a"), ContentHash: hash("b"),
		Marker: MarkerFor(id), State: writeintent.Pending, Version: 1, CreatedAt: t0, UpdatedAt: t0}
}

func page(version int) *RemotePage {
	return &RemotePage{ID: "page-9", Version: version, URL: "https://wiki.example/spaces/SEC/pages/9"}
}

func TestSourceKindFixesTheScope(t *testing.T) {
	for kind, want := range map[SourceKind]Scope{
		EngagementReport:        Engagement,
		AssessmentClosureReport: Project,
		ProjectQualitySummary:   Project,
	} {
		got, ok := kind.Scope()
		if !ok || got != want || !kind.Valid() {
			t.Fatalf("%s scope=%q ok=%t", kind, got, ok)
		}
	}
	for _, kind := range []SourceKind{"", "engagement-report", "ENGAGEMENT_REPORT", "sbom"} {
		if _, ok := kind.Scope(); ok || kind.Valid() {
			t.Fatalf("source kind %q accepted", kind)
		}
	}
}

func TestTargetValidation(t *testing.T) {
	if err := engagementTarget().Validate(); err != nil {
		t.Fatalf("engagement target: %v", err)
	}
	if err := projectTarget().Validate(); err != nil {
		t.Fatalf("project target: %v", err)
	}
	mutations := map[string]func(*Target){
		"engagement report in project scope": func(x *Target) { x.Scope = Project },
		"closure report in engagement scope": func(x *Target) { *x = projectTarget(); x.Scope = Engagement },
		"quality summary in engagement scope": func(x *Target) {
			*x = projectTarget()
			x.SourceKind = ProjectQualitySummary
			x.Scope = Engagement
		},
		"unknown kind":      func(x *Target) { x.SourceKind = "wiki" },
		"missing scope":     func(x *Target) { x.Scope = "" },
		"no integration":    func(x *Target) { x.IntegrationID = "" },
		"no scope id":       func(x *Target) { x.ScopeID = "" },
		"blank source ref":  func(x *Target) { x.SourceRef = "  " },
		"long source ref":   func(x *Target) { x.SourceRef = strings.Repeat("r", maxSourceRefBytes+1) },
		"nul source ref":    func(x *Target) { x.SourceRef = "a\x00b" },
		"bad utf8 ref":      func(x *Target) { x.SourceRef = "a\xffb" },
		"blank container":   func(x *Target) { x.Container = "" },
		"long container":    func(x *Target) { x.Container = strings.Repeat("c", maxContainerBytes+1) },
		"nul container":     func(x *Target) { x.Container = "SEC\x00" },
		"bad utf8 contain.": func(x *Target) { x.Container = "\xc3\x28" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			target := engagementTarget()
			mutate(&target)
			if err := target.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	edge := engagementTarget()
	edge.SourceRef = strings.Repeat("r", maxSourceRefBytes)
	edge.Container = strings.Repeat("c", maxContainerBytes)
	if err := edge.Validate(); err != nil {
		t.Fatalf("bound is inclusive: %v", err)
	}
}

func TestCanonicalURL(t *testing.T) {
	got, err := CanonicalURL(" https://wiki.example/spaces/SEC/pages/9 ")
	if err != nil || got != "https://wiki.example/spaces/SEC/pages/9" {
		t.Fatalf("canonical URL: %q %v", got, err)
	}
	for _, raw := range []string{
		"", "http://wiki.example/p", "ftp://wiki.example/p", "https://", "/relative",
		"https://user:pw@wiki.example/p", "https://wiki.example/p?token=1", "https://wiki.example/p?",
		"https://wiki.example/p#frag", "https://wiki.example/p\x00", "mailto:a@b.c",
		"https://wiki.example/" + strings.Repeat("a", maxURLBytes),
	} {
		if _, err := CanonicalURL(raw); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("URL %q accepted: %v", raw, err)
		}
	}
}

func validLink() Link {
	return Link{ID: "link-1", TenantID: "tenant-a", Target: engagementTarget(), RemotePageID: "page-9",
		RemoteVersion: 1, RemoteURL: "https://wiki.example/spaces/SEC/pages/9", ContentHash: hash("b"),
		Revision: 1, CreatedAt: t0, UpdatedAt: t0}
}

func TestLinkValidation(t *testing.T) {
	if err := validLink().Validate(); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Link){
		"no id":           func(l *Link) { l.ID = "" },
		"no tenant":       func(l *Link) { l.TenantID = "" },
		"bad target":      func(l *Link) { l.Scope = Project },
		"no page":         func(l *Link) { l.RemotePageID = "" },
		"long page":       func(l *Link) { l.RemotePageID = strings.Repeat("p", maxRemotePageBytes+1) },
		"zero version":    func(l *Link) { l.RemoteVersion = 0 },
		"negative":        func(l *Link) { l.RemoteVersion = -1 },
		"http url":        func(l *Link) { l.RemoteURL = "http://wiki.example/p" },
		"noncanonical":    func(l *Link) { l.RemoteURL = "https://wiki.example/p?x=1" },
		"no hash":         func(l *Link) { l.ContentHash = "" },
		"uppercase hash":  func(l *Link) { l.ContentHash = strings.Repeat("B", 64) },
		"short hash":      func(l *Link) { l.ContentHash = strings.Repeat("b", 63) },
		"zero revision":   func(l *Link) { l.Revision = 0 },
		"no created":      func(l *Link) { l.CreatedAt = time.Time{} },
		"updated earlier": func(l *Link) { l.UpdatedAt = l.CreatedAt.Add(-time.Second) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			link := validLink()
			mutate(&link)
			if err := link.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestIntentValidation(t *testing.T) {
	if err := pendingIntent("i-1").Validate(); err != nil {
		t.Fatal(err)
	}
	update := pendingIntent("i-2")
	update.Action = Update
	update.LinkID = "link-1"
	if err := update.Validate(); err != nil {
		t.Fatalf("update intent: %v", err)
	}
	mutations := map[string]func(*Intent){
		"create with link":     func(i *Intent) { i.LinkID = "link-1" },
		"update without link":  func(i *Intent) { i.Action = Update },
		"unknown action":       func(i *Intent) { i.Action = "delete" },
		"empty action":         func(i *Intent) { i.Action = "" },
		"blank request key":    func(i *Intent) { i.RequestKey = " " },
		"long request key":     func(i *Intent) { i.RequestKey = strings.Repeat("k", maxRequestKeyBytes+1) },
		"bad payload digest":   func(i *Intent) { i.PayloadDigest = "xyz" },
		"bad content hash":     func(i *Intent) { i.ContentHash = "" },
		"foreign marker":       func(i *Intent) { i.Marker = "synapse-intent-other" },
		"bad target":           func(i *Intent) { i.Container = "" },
		"invalid state":        func(i *Intent) { i.State = "paused" },
		"zero version":         func(i *Intent) { i.Version = 0 },
		"negative attempts":    func(i *Intent) { i.Attempts = -1 },
		"updated earlier":      func(i *Intent) { i.UpdatedAt = i.CreatedAt.Add(-time.Second) },
		"remote on pending":    func(i *Intent) { i.RemoteID = "page-9" },
		"version on pending":   func(i *Intent) { i.RemoteVersion = 1 },
		"error on pending":     func(i *Intent) { i.ErrorCode = "oops" },
		"failed without code":  func(i *Intent) { i.State = writeintent.Failed },
		"lease without flight": func(i *Intent) { l := t0.Add(time.Minute); i.LeaseUntil = &l },
		"flight without lease": func(i *Intent) { i.State = writeintent.InFlight },
		"done without remote":  func(i *Intent) { i.State = writeintent.Done },
		"malformed error code": func(i *Intent) { i.State = writeintent.Failed; i.ErrorCode = "Bad Code" },
		"uncertain wrong code": func(i *Intent) { i.State = writeintent.Uncertain; i.ErrorCode = "provider_down" },
		"expired flight lease": func(i *Intent) { i.State = writeintent.InFlight; l := t0; i.LeaseUntil = &l },
		"done with error code": func(i *Intent) {
			i.State = writeintent.Done
			i.RemoteID = "p"
			i.RemoteVersion = 1
			i.RemoteURL = "https://w.example/p"
			i.ErrorCode = "x"
		},
		"done with zero ver": func(i *Intent) { i.State = writeintent.Done; i.RemoteID = "p"; i.RemoteURL = "https://w.example/p" },
		"done with plain url": func(i *Intent) {
			i.State = writeintent.Done
			i.RemoteID = "p"
			i.RemoteVersion = 1
			i.RemoteURL = "http://w.example/p"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			intent := pendingIntent("i-3")
			mutate(&intent)
			if err := intent.Validate(); !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestSameCommandIgnoresServerIssuedIdentity(t *testing.T) {
	a := pendingIntent("i-1")
	b := pendingIntent("i-2")
	b.RequestKey = a.RequestKey
	if !a.SameCommand(b) {
		t.Fatal("server-issued ID and marker must not make a replay a different command")
	}
	for name, mutate := range map[string]func(*Intent){
		"tenant":         func(i *Intent) { i.TenantID = "tenant-b" },
		"integration":    func(i *Intent) { i.IntegrationID = "int-2" },
		"source ref":     func(i *Intent) { i.SourceRef = "other" },
		"container":      func(i *Intent) { i.Container = "OPS" },
		"scope id":       func(i *Intent) { i.ScopeID = "eng-2" },
		"action":         func(i *Intent) { i.Action = Update; i.LinkID = "link-1" },
		"request key":    func(i *Intent) { i.RequestKey = "other" },
		"payload digest": func(i *Intent) { i.PayloadDigest = hash("c") },
		"content hash":   func(i *Intent) { i.ContentHash = hash("c") },
	} {
		c := b
		mutate(&c)
		if a.SameCommand(c) {
			t.Fatalf("%s change was treated as the same command", name)
		}
	}
}

func TestApplyFollowsTheSharedStateMachine(t *testing.T) {
	intent := pendingIntent("i-1")
	lease := t0.Add(time.Minute)

	if _, err := intent.Apply(IntentTransition{Event: writeintent.Claim}, t0.Add(time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("claim without lease: %v", err)
	}
	past := t0
	if _, err := intent.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &past}, t0.Add(time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("claim with expired lease: %v", err)
	}
	if _, err := intent.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, t0.Add(-time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("transition before last update: %v", err)
	}
	inFlight, err := intent.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, t0.Add(time.Second))
	if err != nil || inFlight.State != writeintent.InFlight || inFlight.Attempts != 1 || inFlight.Version != 2 || inFlight.LeaseUntil == nil {
		t.Fatalf("claim: %+v %v", inFlight, err)
	}
	*inFlight.LeaseUntil = t0
	again, _ := intent.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, t0.Add(time.Second))
	if again.LeaseUntil == nil || !again.LeaseUntil.Equal(lease) {
		t.Fatal("applying a claim must not alias the caller's lease")
	}
	inFlight, _ = intent.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, t0.Add(time.Second))

	if _, err = inFlight.Apply(IntentTransition{Event: writeintent.Acknowledge}, t0.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("acknowledge without a remote page: %v", err)
	}
	if _, err = inFlight.Apply(IntentTransition{Event: writeintent.Acknowledge, Remote: &RemotePage{ID: "p", URL: "https://w.example/p"}}, t0.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("acknowledge without a remote version: %v", err)
	}
	if _, err = inFlight.Apply(IntentTransition{Event: writeintent.Ambiguous, Remote: page(1)}, t0.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("remote page on a non-completing transition: %v", err)
	}
	if _, err = inFlight.Apply(IntentTransition{Event: writeintent.Acknowledge, Remote: page(1), LeaseUntil: &lease}, t0.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("lease on a non-claim transition: %v", err)
	}
	if _, err = inFlight.Apply(IntentTransition{Event: writeintent.Acknowledge, Remote: page(1), ErrorCode: "x"}, t0.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("error code on acknowledge: %v", err)
	}
	done, err := inFlight.Apply(IntentTransition{Event: writeintent.Acknowledge, Remote: page(1)}, t0.Add(2*time.Second))
	if err != nil || done.State != writeintent.Done || done.RemoteID != "page-9" || done.RemoteVersion != 1 || done.LeaseUntil != nil {
		t.Fatalf("acknowledge: %+v %v", done, err)
	}
	if _, err = done.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, t0.Add(3*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("a done intent was claimed again: %v", err)
	}
}

func TestApplyNeverRepeatsAnUncertainWrite(t *testing.T) {
	lease := t0.Add(time.Minute)
	inFlight, err := pendingIntent("i-1").Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inFlight.Apply(IntentTransition{Event: writeintent.LeaseExpired}, lease.Add(-time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("lease expiry before the lease ended: %v", err)
	}
	uncertain, err := inFlight.Apply(IntentTransition{Event: writeintent.LeaseExpired}, lease)
	if err != nil || uncertain.State != writeintent.Uncertain || uncertain.LeaseUntil != nil {
		t.Fatalf("lease expiry: %+v %v", uncertain, err)
	}
	if _, err = uncertain.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, lease.Add(time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("an uncertain write was repeated without reconciliation: %v", err)
	}
	multiple, err := uncertain.Apply(IntentTransition{Event: writeintent.ReconcileMultiple}, lease.Add(time.Second))
	if err != nil || multiple.State != writeintent.Uncertain || multiple.ErrorCode != "multiple_matches" {
		t.Fatalf("multiple matches: %+v %v", multiple, err)
	}
	if _, err = uncertain.Apply(IntentTransition{Event: writeintent.ReconcileMultiple, ErrorCode: "mine"}, lease.Add(time.Second)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("caller supplied a multiple-match code: %v", err)
	}
	if _, err = multiple.Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, lease.Add(2*time.Second)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("multiple matches allowed a retry: %v", err)
	}
	absent, err := uncertain.Apply(IntentTransition{Event: writeintent.ReconcileAbsent}, lease.Add(time.Second))
	if err != nil || absent.State != writeintent.Pending || absent.ErrorCode != "" {
		t.Fatalf("reconcile absent: %+v %v", absent, err)
	}
	found, err := multiple.Apply(IntentTransition{Event: writeintent.ReconcileFound, Remote: page(3)}, lease.Add(2*time.Second))
	if err != nil || found.State != writeintent.Done || found.ErrorCode != "" || found.RemoteVersion != 3 {
		t.Fatalf("reconcile found clears the multiple-match code: %+v %v", found, err)
	}
}

func TestApplyClassifiesRejections(t *testing.T) {
	lease := t0.Add(time.Minute)
	inFlight, _ := pendingIntent("i-1").Apply(IntentTransition{Event: writeintent.Claim, LeaseUntil: &lease}, t0.Add(time.Second))
	for _, code := range []string{"", "Provider Said No", "HTTP 403: <html>", strings.Repeat("a", 65)} {
		if _, err := inFlight.Apply(IntentTransition{Event: writeintent.Reject, ErrorCode: code}, t0.Add(2*time.Second)); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("rejection code %q accepted: %v", code, err)
		}
	}
	failed, err := inFlight.Apply(IntentTransition{Event: writeintent.Reject, ErrorCode: "provider_rejected"}, t0.Add(2*time.Second))
	if err != nil || failed.State != writeintent.Failed || failed.ErrorCode != "provider_rejected" {
		t.Fatalf("reject: %+v %v", failed, err)
	}
	retried, err := failed.Apply(IntentTransition{Event: writeintent.RetryFailed}, t0.Add(3*time.Second))
	if err != nil || retried.State != writeintent.Pending || retried.ErrorCode != "" {
		t.Fatalf("retry failed: %+v %v", retried, err)
	}
}

func doneIntent(id shared.ID, action Action, link shared.ID, version int, content string) Intent {
	i := pendingIntent(id)
	i.Action = action
	i.LinkID = link
	i.ContentHash = hash(content)
	i.State = writeintent.Done
	i.Version = 4
	i.Attempts = 1
	i.RemoteID = "page-9"
	i.RemoteURL = "https://wiki.example/spaces/SEC/pages/9"
	i.RemoteVersion = version
	i.UpdatedAt = t0.Add(time.Hour)
	return i
}

func TestCompleteCreatesTheLinkFromTheIntent(t *testing.T) {
	intent := doneIntent("i-create", Create, "", 1, "b")
	link, changed, err := intent.Complete(nil)
	if err != nil || !changed {
		t.Fatalf("complete: %+v %t %v", link, changed, err)
	}
	if link.ID != intent.ID || link.TenantID != intent.TenantID || link.Target != intent.Target ||
		link.RemotePageID != "page-9" || link.RemoteVersion != 1 || link.ContentHash != hash("b") ||
		link.Revision != 1 || !link.CreatedAt.Equal(intent.UpdatedAt) || !link.UpdatedAt.Equal(intent.UpdatedAt) {
		t.Fatalf("created link: %+v", link)
	}
}

func TestCompleteRefusesWhatIsNotDone(t *testing.T) {
	if _, _, err := pendingIntent("i-1").Complete(nil); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("pending intent completed: %v", err)
	}
	if _, _, err := (Intent{}).Complete(nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("zero intent completed: %v", err)
	}
}

func TestCompleteAdvancesALinkOnlyForward(t *testing.T) {
	existing := validLink()
	existing.RemoteVersion = 3
	existing.Revision = 2
	existing.ContentHash = hash("c")

	t.Run("newer version replaces the content", func(t *testing.T) {
		intent := doneIntent("i-update", Update, existing.ID, 4, "d")
		link, changed, err := intent.Complete(&existing)
		if err != nil || !changed {
			t.Fatalf("complete: %+v %t %v", link, changed, err)
		}
		if link.ID != existing.ID || !link.CreatedAt.Equal(existing.CreatedAt) || link.RemoteVersion != 4 ||
			link.ContentHash != hash("d") || link.Revision != 3 || !link.UpdatedAt.Equal(intent.UpdatedAt) {
			t.Fatalf("updated link: %+v", link)
		}
		if existing.RemoteVersion != 3 || existing.Revision != 2 {
			t.Fatalf("completion mutated the stored link: %+v", existing)
		}
	})
	t.Run("a late older write leaves the link alone", func(t *testing.T) {
		intent := doneIntent("i-late", Update, existing.ID, 2, "d")
		link, changed, err := intent.Complete(&existing)
		if err != nil || changed || link.RemoteVersion != 3 || link.ContentHash != hash("c") || link.Revision != 2 {
			t.Fatalf("stale completion: %+v %t %v", link, changed, err)
		}
	})
	t.Run("the same version and content is a replay", func(t *testing.T) {
		intent := doneIntent("i-replay", Update, existing.ID, 3, "c")
		link, changed, err := intent.Complete(&existing)
		if err != nil || changed || link.Revision != 2 {
			t.Fatalf("replay: %+v %t %v", link, changed, err)
		}
	})
	t.Run("the same version with other content is a conflict", func(t *testing.T) {
		intent := doneIntent("i-diverge", Update, existing.ID, 3, "d")
		if _, _, err := intent.Complete(&existing); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("diverging content accepted: %v", err)
		}
	})
	t.Run("a different page never replaces the identity", func(t *testing.T) {
		intent := doneIntent("i-other-page", Update, existing.ID, 9, "d")
		intent.RemoteID = "page-other"
		if _, _, err := intent.Complete(&existing); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("page identity replaced: %v", err)
		}
	})
	t.Run("a create that found the same page converges", func(t *testing.T) {
		intent := doneIntent("i-create-again", Create, "", 4, "d")
		link, changed, err := intent.Complete(&existing)
		if err != nil || !changed || link.ID != existing.ID || link.RemoteVersion != 4 {
			t.Fatalf("create over its own page: %+v %t %v", link, changed, err)
		}
	})
	t.Run("a create that produced another page conflicts", func(t *testing.T) {
		intent := doneIntent("i-duplicate-page", Create, "", 1, "b")
		intent.RemoteID = "page-duplicate"
		if _, _, err := intent.Complete(&existing); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("duplicate page adopted: %v", err)
		}
	})
	t.Run("an update needs its link", func(t *testing.T) {
		intent := doneIntent("i-orphan", Update, existing.ID, 4, "d")
		if _, _, err := intent.Complete(nil); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("update completed without a link: %v", err)
		}
	})
	t.Run("an update for another link conflicts", func(t *testing.T) {
		intent := doneIntent("i-wrong-link", Update, "link-other", 4, "d")
		if _, _, err := intent.Complete(&existing); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("update completed against another link: %v", err)
		}
	})
	t.Run("another target conflicts", func(t *testing.T) {
		intent := doneIntent("i-other-target", Update, existing.ID, 4, "d")
		intent.Container = "OPS"
		if _, _, err := intent.Complete(&existing); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("completed against another target: %v", err)
		}
	})
	t.Run("another tenant conflicts", func(t *testing.T) {
		intent := doneIntent("i-other-tenant", Update, existing.ID, 4, "d")
		intent.TenantID = "tenant-b"
		if _, _, err := intent.Complete(&existing); !errors.Is(err, shared.ErrConflict) {
			t.Fatalf("completed against another tenant's link: %v", err)
		}
	})
	t.Run("an invalid stored link is refused", func(t *testing.T) {
		broken := existing
		broken.ContentHash = ""
		intent := doneIntent("i-broken", Update, existing.ID, 4, "d")
		if _, _, err := intent.Complete(&broken); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("completed against an invalid link: %v", err)
		}
	})
}

func TestUpdatedAtNeverMovesBackwards(t *testing.T) {
	existing := validLink()
	existing.UpdatedAt = t0.Add(48 * time.Hour)
	intent := doneIntent("i-old-clock", Update, existing.ID, 2, "d")
	link, changed, err := intent.Complete(&existing)
	if err != nil || !changed || !link.UpdatedAt.Equal(existing.UpdatedAt) {
		t.Fatalf("link time moved back: %+v %t %v", link, changed, err)
	}
}
