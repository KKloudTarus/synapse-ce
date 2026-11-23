// Package docpublish models tenant-scoped links to published documents and the durable
// write intents that create or update them. A remote write with an unknown outcome is
// never blindly repeated; that rule lives in the shared writeintent state machine.
//
// A Link is the current state of one remote page. An Intent is one publish or republish
// attempt: it reaches done once and is then history, while the link it completed keeps
// being updated by later intents.
package docpublish

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/writeintent"
)

// MaxListLimit is the most links one listing returns. A scope can accumulate links over
// time, so no consumer gets an unbounded read.
const MaxListLimit = 100

// DestinationManagedSnapshotProfile records that a provider, not Synapse, owns
// effective sharing for an immutable snapshot destination.
const DestinationManagedSnapshotProfile = "destination_managed_snapshot_v1"

// Persistence-compatible bounds. The migration's CHECK constraints repeat them.
const (
	maxSourceRefBytes      = 512
	maxContainerBytes      = 255
	maxRemotePageBytes     = 512
	maxRemoteRevisionBytes = 512
	maxURLBytes            = 2048
	maxRequestKeyBytes     = 128
	maxMarkerBytes         = 256
	markerPrefix           = "synapse-intent-"
	multipleMatchesCode    = "multiple_matches"
)

// SourceKind is the stored artifact a document is rendered from. The set is closed on
// purpose: each kind fixes the scope its links live in and how a publisher hashes it.
type SourceKind string

const (
	EngagementReport        SourceKind = "engagement_report"
	AssessmentClosureReport SourceKind = "assessment_closure_report"
	ProjectQualitySummary   SourceKind = "project_quality_summary"
)

// Scope is the tenant-owned parent a link hangs from.
type Scope string

const (
	Engagement Scope = "engagement"
	Project    Scope = "project"
)

// Scope returns the one scope a source kind can be published from. The engagement report
// is rendered per engagement; the closure report belongs to an assessment cycle, which is
// project scoped; the quality summary describes a project.
func (k SourceKind) Scope() (Scope, bool) {
	switch k {
	case EngagementReport:
		return Engagement, true
	case AssessmentClosureReport, ProjectQualitySummary:
		return Project, true
	}
	return "", false
}

func (k SourceKind) Valid() bool {
	_, ok := k.Scope()
	return ok
}

// Target names the remote document a link or intent is about. Two writes with the same
// Target address the same page; a different Container is a different page.
type Target struct {
	IntegrationID shared.ID
	SourceKind    SourceKind
	// SourceRef identifies the artifact within its kind. It is opaque to this package: the
	// engagement report is rendered on demand, the closure report is stored per cycle,
	// manifest and renderer version, and the publisher decides how to name each of them.
	SourceRef string
	Scope     Scope
	ScopeID   shared.ID
	// Container is the remote place the page lives in, such as a Confluence space key.
	// The page's parent inside that container is a creation attribute, not an identity.
	Container string
}

func (t Target) Validate() error {
	scope, ok := t.SourceKind.Scope()
	if !ok {
		return fmt.Errorf("%w: invalid document source kind", shared.ErrValidation)
	}
	if t.Scope != scope {
		return fmt.Errorf("%w: document source kind %s requires %s scope", shared.ErrValidation, t.SourceKind, scope)
	}
	if t.IntegrationID.IsZero() || t.ScopeID.IsZero() ||
		!bounded(t.SourceRef, maxSourceRefBytes) || !bounded(t.Container, maxContainerBytes) {
		return fmt.Errorf("%w: invalid document target", shared.ErrValidation)
	}
	return nil
}

func validText(v string) bool { return utf8.ValidString(v) && !strings.ContainsRune(v, 0) }

func bounded(v string, max int) bool {
	return validText(v) && strings.TrimSpace(v) != "" && len(v) <= max
}

// CanonicalURL refuses credentials, query-string tokens, fragments and non-HTTPS schemes.
// A document URL is display-only and is never fetched.
func CanonicalURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !validText(raw) || u.Scheme != "https" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || len(raw) > maxURLBytes {
		return "", fmt.Errorf("%w: document URL must be HTTPS without credentials, query or fragment", shared.ErrValidation)
	}
	return u.String(), nil
}

var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var errorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// RemotePage is the provider identity recorded after a successful remote write.
type RemotePage struct {
	ID string
	// Version is the provider numeric page version. Providers that only expose
	// an opaque revision retain the compatible sentinel value 1 here.
	Version int
	// Revision is an opaque provider concurrency token. It is never parsed,
	// hashed, or used for arithmetic.
	Revision string
	URL      string
}

func (r RemotePage) validate() error {
	if !bounded(r.ID, maxRemotePageBytes) || r.Version < 1 {
		return fmt.Errorf("%w: remote page needs a bounded ID and a version", shared.ErrValidation)
	}
	if r.Revision != "" && !bounded(r.Revision, maxRemoteRevisionBytes) {
		return fmt.Errorf("%w: remote page revision must be a bounded opaque token", shared.ErrValidation)
	}
	return validCanonicalURL(r.URL)
}

func validCanonicalURL(raw string) error {
	normalized, err := CanonicalURL(raw)
	if err != nil || normalized != raw {
		return fmt.Errorf("%w: document URL must be canonical HTTPS", shared.ErrValidation)
	}
	return nil
}

// Link is the current state of one published page.
type Link struct {
	ID       shared.ID
	TenantID shared.ID
	Target
	RemotePageID   string
	RemoteVersion  int
	RemoteRevision string
	RemoteURL      string
	ContentHash    string
	AccessProfile  string
	// Revision counts the writes applied to this link, starting at 1.
	Revision int
	// RestrictionStatus describes the last background sharing observation, not
	// a guarantee that a remote administrator cannot change access afterwards.
	RestrictionStatus       string
	RestrictionCheckedAt    *time.Time
	RestrictionNextAt       time.Time
	RestrictionCheckVersion int
	// RetiredAt retains the page's immutable identity after a governed purge.
	// A retired target cannot be created or updated again.
	RetiredAt   *time.Time
	RemovalKind RemovalKind
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (l Link) Validate() error {
	if l.ID.IsZero() || l.TenantID.IsZero() || l.Revision < 1 ||
		l.CreatedAt.IsZero() || l.UpdatedAt.Before(l.CreatedAt) {
		return fmt.Errorf("%w: invalid document link", shared.ErrValidation)
	}
	if l.RetiredAt != nil && (l.RetiredAt.Before(l.CreatedAt) || l.RetiredAt.Before(l.UpdatedAt) || !l.RemovalKind.Valid()) {
		return fmt.Errorf("%w: document retirement time is invalid", shared.ErrValidation)
	}
	if l.RetiredAt == nil && l.RemovalKind != "" {
		return fmt.Errorf("%w: active document link has a removal kind", shared.ErrValidation)
	}
	if err := l.Target.Validate(); err != nil {
		return err
	}
	if err := (RemotePage{ID: l.RemotePageID, Version: l.RemoteVersion, Revision: l.RemoteRevision, URL: l.RemoteURL}).validate(); err != nil {
		return err
	}
	if !sha256Pattern.MatchString(l.ContentHash) {
		return fmt.Errorf("%w: document link needs a content hash", shared.ErrValidation)
	}
	if l.AccessProfile != "" && l.AccessProfile != DestinationManagedSnapshotProfile {
		return fmt.Errorf("%w: invalid document access profile", shared.ErrValidation)
	}
	return nil
}

type Action string

const (
	// Create writes a page that does not exist yet. Unpublishing is a different remote
	// write with its own reconciliation rules and is not modelled here.
	Create Action = "create"
	// Update writes a new version of the page an existing link points to.
	Update Action = "update"
	// Purge permanently removes a previously published page and retires its
	// local target. It cannot create a replacement page for that target.
	Purge    Action = "purge"
	Snapshot Action = "snapshot"
	Trash    Action = "trash"
)

type RemovalKind string

const (
	RemovalTrash RemovalKind = "trash"
	RemovalPurge RemovalKind = "purge"
)

func (k RemovalKind) Valid() bool { return k == RemovalTrash || k == RemovalPurge }

// Intent is one durable publish or republish command.
type Intent struct {
	ID       shared.ID
	TenantID shared.ID
	Target
	// LinkID names the link an Update writes to. It is empty for Create.
	LinkID shared.ID
	// ExpectedLinkRevision fences managed snapshots and trash from advancing a
	// link changed by another completed publication.
	ExpectedLinkRevision int
	Action               Action
	// RequestKey is the logical command identity; PayloadDigest covers the command content,
	// so a replay with different content is a conflict rather than a second write.
	RequestKey    string
	PayloadDigest string
	// ContentHash is the hash of the document body this intent publishes.
	ContentHash   string
	AccessProfile string
	Marker        string
	State         writeintent.State
	Version       int
	Attempts      int
	LeaseUntil    *time.Time
	// RemoteID, RemoteURL, RemoteVersion and RemoteRevision are the page this write produced; set only when done.
	RemoteID       string
	RemoteURL      string
	RemoteVersion  int
	RemoteRevision string
	ErrorCode      string // stable classification only; no raw HTTP/provider errors
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IntentTransition supplies the evidence for one state-machine transition.
// Remote is required only for transitions that finish a remote write.
type IntentTransition struct {
	Event      writeintent.Event
	LeaseUntil *time.Time
	Remote     *RemotePage
	ErrorCode  string
	Resumable  bool
}

// MarkerFor derives the correlation marker a remote object carries for an intent ID.
func MarkerFor(id shared.ID) string { return markerPrefix + id.String() }

func (i Intent) Validate() error {
	if i.ID.IsZero() || i.TenantID.IsZero() || !bounded(i.RequestKey, maxRequestKeyBytes) ||
		!sha256Pattern.MatchString(i.PayloadDigest) || !sha256Pattern.MatchString(i.ContentHash) ||
		i.Marker != MarkerFor(i.ID) || len(i.Marker) > maxMarkerBytes ||
		!i.State.Valid() || i.Version < 1 || i.Attempts < 0 || i.CreatedAt.IsZero() ||
		i.UpdatedAt.Before(i.CreatedAt) {
		return fmt.Errorf("%w: invalid document intent", shared.ErrValidation)
	}
	if err := i.Target.Validate(); err != nil {
		return err
	}
	if i.AccessProfile != "" && i.AccessProfile != DestinationManagedSnapshotProfile {
		return fmt.Errorf("%w: invalid document access profile", shared.ErrValidation)
	}
	switch i.Action {
	case Create:
		if !i.LinkID.IsZero() || i.ExpectedLinkRevision != 0 {
			return fmt.Errorf("%w: a create intent has no existing link", shared.ErrValidation)
		}
	case Update, Purge, Snapshot, Trash:
		if i.LinkID.IsZero() {
			return fmt.Errorf("%w: a document update, snapshot or removal needs an existing link", shared.ErrValidation)
		}
		if (i.Action == Snapshot || i.Action == Trash) && i.ExpectedLinkRevision < 1 {
			return fmt.Errorf("%w: document snapshot or trash needs expected link revision", shared.ErrValidation)
		}
		if (i.Action == Snapshot || i.Action == Trash) && i.AccessProfile != DestinationManagedSnapshotProfile {
			return fmt.Errorf("%w: document snapshot or trash requires a managed access profile", shared.ErrValidation)
		}
		if i.Action != Snapshot && i.Action != Trash && i.ExpectedLinkRevision != 0 {
			return fmt.Errorf("%w: only document snapshot or trash has an expected link revision", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: invalid document intent action", shared.ErrValidation)
	}
	if i.ErrorCode != "" && !errorCodePattern.MatchString(i.ErrorCode) {
		return fmt.Errorf("%w: document intent error code must be a bounded classification", shared.ErrValidation)
	}
	if (i.State == writeintent.InFlight) != (i.LeaseUntil != nil) {
		return fmt.Errorf("%w: only in-flight document intents have a lease", shared.ErrValidation)
	}
	if i.LeaseUntil != nil && !i.LeaseUntil.After(i.UpdatedAt) {
		return fmt.Errorf("%w: document intent lease must be in the future", shared.ErrValidation)
	}
	if i.State == writeintent.Done {
		if err := (RemotePage{ID: i.RemoteID, Version: i.RemoteVersion, Revision: i.RemoteRevision, URL: i.RemoteURL}).validate(); err != nil {
			return err
		}
		if i.ErrorCode != "" {
			return fmt.Errorf("%w: completed document intent cannot have an error code", shared.ErrValidation)
		}
	} else if i.RemoteID != "" || i.RemoteURL != "" || i.RemoteVersion != 0 || i.RemoteRevision != "" {
		return fmt.Errorf("%w: only completed document intents have a remote page", shared.ErrValidation)
	}
	if i.State == writeintent.Failed && i.ErrorCode == "" {
		return fmt.Errorf("%w: failed document intent needs an error code", shared.ErrValidation)
	}
	if i.State != writeintent.Failed && i.State != writeintent.Uncertain && i.ErrorCode != "" {
		return fmt.Errorf("%w: only failed or uncertain document intents have an error code", shared.ErrValidation)
	}
	if i.State == writeintent.Uncertain && i.ErrorCode != "" && i.ErrorCode != multipleMatchesCode {
		return fmt.Errorf("%w: uncertain document intent has an invalid error code", shared.ErrValidation)
	}
	return nil
}

// ReconcileResumable is intentionally document-local: a conclusive checkpoint
// permits an uncertain document command to resume, while other write domains
// continue to reject an unknown event.
const ReconcileResumable writeintent.Event = "reconcile_resumable"

// CheckpointYield is intentionally document-local: a worker that has durably
// checkpointed one acknowledged remote effect yields its lease so the next
// slice can continue immediately without consuming a failure retry.
const CheckpointYield writeintent.Event = "checkpoint_yield"

// RetryDeferred is intentionally document-local. It releases only a clean
// in-flight pre-write claim after a provider throttle, so retry accounting is
// not consumed by repeated read-only 429 responses.
const RetryDeferred writeintent.Event = "retry_deferred"

// SameCommand reports whether two intents are the same logical command, which is what a
// replayed request key must be. Identity fields that the server issues (ID, marker, state,
// timestamps) are deliberately not compared.
func (i Intent) SameCommand(other Intent) bool {
	return i.TenantID == other.TenantID && i.Target == other.Target && i.LinkID == other.LinkID && i.ExpectedLinkRevision == other.ExpectedLinkRevision && i.AccessProfile == other.AccessProfile &&
		i.Action == other.Action && i.RequestKey == other.RequestKey &&
		i.PayloadDigest == other.PayloadDigest && i.ContentHash == other.ContentHash
}

// Apply advances an intent using the evidence recorded by the caller. It is pure so
// every durable adapter can validate the identical outcome before storing it.
func (i Intent) Apply(change IntentTransition, at time.Time) (Intent, error) {
	if err := i.Validate(); err != nil {
		return Intent{}, err
	}
	if at.IsZero() || at.Before(i.UpdatedAt) {
		return Intent{}, fmt.Errorf("%w: document intent transition time is invalid", shared.ErrValidation)
	}
	var (
		next writeintent.State
		err  error
	)
	if change.Event == ReconcileResumable {
		if i.State != writeintent.Uncertain || !change.Resumable {
			return Intent{}, fmt.Errorf("%w: document reconciliation is not resumable", shared.ErrConflict)
		}
		next = writeintent.Pending
	} else if change.Event == CheckpointYield {
		if i.State != writeintent.InFlight || i.LeaseUntil == nil || !at.Before(*i.LeaseUntil) || change.Resumable {
			return Intent{}, fmt.Errorf("%w: document checkpoint is not yieldable", shared.ErrConflict)
		}
		next = writeintent.Pending
	} else if change.Event == RetryDeferred {
		if i.State != writeintent.InFlight || i.LeaseUntil == nil || !at.Before(*i.LeaseUntil) || change.Resumable {
			return Intent{}, fmt.Errorf("%w: document retry is not deferrable", shared.ErrConflict)
		}
		next = writeintent.Pending
	} else {
		if change.Resumable {
			return Intent{}, fmt.Errorf("%w: resumable evidence only applies to document reconciliation", shared.ErrValidation)
		}
		next, err = writeintent.Next(i.State, change.Event)
		if err != nil {
			return Intent{}, err
		}
	}
	if change.Event == writeintent.LeaseExpired &&
		(i.LeaseUntil == nil || at.Before(*i.LeaseUntil)) {
		return Intent{}, fmt.Errorf("%w: document intent lease has not expired", shared.ErrConflict)
	}
	if change.Event == writeintent.Claim {
		if change.LeaseUntil == nil || !change.LeaseUntil.After(at) {
			return Intent{}, fmt.Errorf("%w: document intent claim needs a future lease", shared.ErrValidation)
		}
		lease := change.LeaseUntil.UTC()
		i.LeaseUntil = &lease
		i.Attempts++
	} else {
		if change.LeaseUntil != nil {
			return Intent{}, fmt.Errorf("%w: only a document intent claim may set a lease", shared.ErrValidation)
		}
		i.LeaseUntil = nil
		if change.Event == CheckpointYield || change.Event == RetryDeferred {
			if i.Attempts < 1 {
				return Intent{}, fmt.Errorf("%w: document retry has no claimed attempt", shared.ErrConflict)
			}
			i.Attempts--
		}
	}
	if next == writeintent.Done {
		if change.Remote == nil {
			return Intent{}, fmt.Errorf("%w: completed document intent needs a remote page", shared.ErrValidation)
		}
		if err := change.Remote.validate(); err != nil {
			return Intent{}, err
		}
		i.RemoteID = change.Remote.ID
		i.RemoteURL = change.Remote.URL
		i.RemoteVersion = change.Remote.Version
		i.RemoteRevision = change.Remote.Revision
	} else {
		if change.Remote != nil {
			return Intent{}, fmt.Errorf("%w: only a completed document intent may set a remote page", shared.ErrValidation)
		}
		i.RemoteID = ""
		i.RemoteURL = ""
		i.RemoteVersion = 0
		i.RemoteRevision = ""
	}
	switch change.Event {
	case writeintent.Reject:
		if !errorCodePattern.MatchString(change.ErrorCode) {
			return Intent{}, fmt.Errorf("%w: rejected document intent needs a bounded error code", shared.ErrValidation)
		}
		i.ErrorCode = change.ErrorCode
	case writeintent.ReconcileMultiple:
		if change.ErrorCode != "" {
			return Intent{}, fmt.Errorf("%w: reconciliation derives its multiple-match code", shared.ErrValidation)
		}
		i.ErrorCode = multipleMatchesCode
	default:
		if change.ErrorCode != "" {
			return Intent{}, fmt.Errorf("%w: only a rejection supplies an error code", shared.ErrValidation)
		}
		i.ErrorCode = ""
	}
	i.State = next
	i.Version++
	i.UpdatedAt = at.UTC()
	if err := i.Validate(); err != nil {
		return Intent{}, err
	}
	return i, nil
}

// Complete returns the link a done intent leaves behind. existing is the link currently
// stored for the intent's target, or nil when there is none. The boolean reports whether
// the stored link has to be written.
//
// A page's identity is never replaced, and a link never moves back to an older remote
// version: a write that finished after a newer one is history, not the current state.
func (i Intent) Complete(existing *Link) (Link, bool, error) {
	if err := i.Validate(); err != nil {
		return Link{}, false, err
	}
	if i.State != writeintent.Done {
		return Link{}, false, fmt.Errorf("%w: only a completed document intent has a completion link", shared.ErrConflict)
	}
	if existing == nil {
		if i.Action != Create {
			return Link{}, false, fmt.Errorf("%w: the document link this update writes to no longer exists", shared.ErrConflict)
		}
		link := Link{
			ID: i.ID, TenantID: i.TenantID, Target: i.Target,
			RemotePageID: i.RemoteID, RemoteVersion: i.RemoteVersion, RemoteRevision: i.RemoteRevision, RemoteURL: i.RemoteURL,
			ContentHash: i.ContentHash, AccessProfile: i.AccessProfile, Revision: 1, CreatedAt: i.UpdatedAt, UpdatedAt: i.UpdatedAt,
		}
		if err := link.Validate(); err != nil {
			return Link{}, false, err
		}
		return link, true, nil
	}
	if err := existing.Validate(); err != nil {
		return Link{}, false, err
	}
	if existing.TenantID != i.TenantID || existing.Target != i.Target {
		return Link{}, false, fmt.Errorf("%w: document link target differs", shared.ErrConflict)
	}
	if existing.AccessProfile != i.AccessProfile {
		return Link{}, false, fmt.Errorf("%w: document access profile differs", shared.ErrConflict)
	}
	if (i.Action == Update || i.Action == Purge || i.Action == Snapshot || i.Action == Trash) && existing.ID != i.LinkID {
		return Link{}, false, fmt.Errorf("%w: document update targets another link", shared.ErrConflict)
	}
	if i.Action != Snapshot && existing.RemotePageID != i.RemoteID {
		return Link{}, false, fmt.Errorf("%w: document page identity differs", shared.ErrConflict)
	}
	if existing.RetiredAt != nil && (i.Action != Snapshot || existing.RemovalKind != RemovalTrash || i.AccessProfile != DestinationManagedSnapshotProfile) {
		return Link{}, false, fmt.Errorf("%w: document link is retired", shared.ErrConflict)
	}
	if i.Action == Purge || i.Action == Trash {
		if i.RemoteVersion != existing.RemoteVersion || i.RemoteRevision != existing.RemoteRevision || i.RemoteURL != existing.RemoteURL {
			return Link{}, false, fmt.Errorf("%w: document removal must retain the existing page identity and version", shared.ErrConflict)
		}
		if i.ExpectedLinkRevision > 0 && i.ExpectedLinkRevision != existing.Revision {
			return Link{}, false, fmt.Errorf("%w: document removal link revision differs", shared.ErrConflict)
		}
		next := *existing
		retired := i.UpdatedAt.UTC()
		next.RetiredAt = &retired
		if i.Action == Trash {
			next.RemovalKind = RemovalTrash
		} else {
			next.RemovalKind = RemovalPurge
		}
		next.UpdatedAt = retired
		next.Revision++
		if err := next.Validate(); err != nil {
			return Link{}, false, err
		}
		return next, true, nil
	}
	if i.Action == Snapshot {
		if i.ExpectedLinkRevision != existing.Revision {
			return Link{}, false, fmt.Errorf("%w: document snapshot link revision differs", shared.ErrConflict)
		}
		next := *existing
		next.RemotePageID, next.RemoteVersion, next.RemoteRevision, next.RemoteURL = i.RemoteID, i.RemoteVersion, i.RemoteRevision, i.RemoteURL
		next.ContentHash, next.AccessProfile = i.ContentHash, i.AccessProfile
		next.RetiredAt, next.RemovalKind = nil, ""
		next.RestrictionStatus, next.RestrictionCheckedAt, next.RestrictionNextAt, next.RestrictionCheckVersion = "", nil, time.Time{}, 0
		next.Revision++
		next.UpdatedAt = i.UpdatedAt.UTC()
		if err := next.Validate(); err != nil {
			return Link{}, false, err
		}
		return next, true, nil
	}
	if i.RemoteRevision != "" || existing.RemoteRevision != "" {
		if i.RemoteRevision == "" || existing.RemoteRevision == "" {
			return Link{}, false, fmt.Errorf("%w: document remote revision type differs", shared.ErrConflict)
		}
		if i.RemoteRevision == existing.RemoteRevision {
			if existing.ContentHash != i.ContentHash {
				return Link{}, false, fmt.Errorf("%w: document revision recorded with different content", shared.ErrConflict)
			}
			return *existing, false, nil
		}
		next := *existing
		next.RemoteVersion = i.RemoteVersion
		next.RemoteRevision = i.RemoteRevision
		next.RemoteURL = i.RemoteURL
		next.ContentHash = i.ContentHash
		next.Revision++
		if i.UpdatedAt.After(next.UpdatedAt) {
			next.UpdatedAt = i.UpdatedAt
		}
		if err := next.Validate(); err != nil {
			return Link{}, false, err
		}
		return next, true, nil
	}
	switch {
	case i.RemoteVersion < existing.RemoteVersion:
		return *existing, false, nil
	case i.RemoteVersion == existing.RemoteVersion:
		if existing.ContentHash != i.ContentHash {
			return Link{}, false, fmt.Errorf("%w: document version recorded with different content", shared.ErrConflict)
		}
		return *existing, false, nil
	}
	next := *existing
	next.RemoteVersion = i.RemoteVersion
	next.RemoteRevision = i.RemoteRevision
	next.RemoteURL = i.RemoteURL
	next.ContentHash = i.ContentHash
	next.Revision++
	if i.UpdatedAt.After(next.UpdatedAt) {
		next.UpdatedAt = i.UpdatedAt
	}
	if err := next.Validate(); err != nil {
		return Link{}, false, err
	}
	return next, true, nil
}

func (i Intent) Clone() Intent {
	if i.LeaseUntil != nil {
		at := *i.LeaseUntil
		i.LeaseUntil = &at
	}
	return i
}

func (l Link) Clone() Link {
	if l.RestrictionCheckedAt != nil {
		at := *l.RestrictionCheckedAt
		l.RestrictionCheckedAt = &at
	}
	if l.RetiredAt != nil {
		at := *l.RetiredAt
		l.RetiredAt = &at
	}
	return l
}
