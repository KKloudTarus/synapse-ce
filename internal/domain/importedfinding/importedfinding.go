// Package importedfinding models a finding produced by a THIRD-PARTY scanner and ingested into this
// system's governance path.
//
// The whole point of the type is that an external result is never presented as this system's own
// analysis. Provenance is mandatory and immutable: a finding whose tool, rule and source document cannot
// be established is refused rather than stored, because an unattributable finding cannot be reasoned
// about, disputed, or re-checked against its source.
//
// An imported finding also carries no promotion authority. An external tool's confidence is not a
// distinct verifier's sealed verdict, so it participates in the finding lifecycle without ever being
// able to promote itself through the judgment gate.
package importedfinding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Provenance is the immutable record of where an imported finding came from. Every field is required:
// together they let a reader re-derive the finding from its source document.
type Provenance struct {
	// ToolName and ToolVersion identify the scanner that produced the result.
	ToolName    string
	ToolVersion string
	// RuleID is the tool's own rule identifier.
	RuleID string
	// SourceDigest is the SHA-256 of the exact document ingested, which makes ingest idempotent and
	// lets a dispute be settled against the original bytes.
	SourceDigest string
	// IngestedBy is the actor who performed the ingest, and IngestedAt when.
	IngestedBy shared.ID
	IngestedAt time.Time
}

// Validate reports whether the provenance is complete. A partial provenance is refused rather than
// stored, because it cannot be attributed.
//
// The required fields are checked in a fixed order from a fixed list, so the error text is deterministic
// without a per-call map allocation and sort — this runs once per finding inside every store's batch.
func (p Provenance) Validate() error {
	required := [...]struct{ name, value string }{
		{"rule id", p.RuleID},
		{"source digest", p.SourceDigest},
		{"tool name", p.ToolName},
		{"tool version", p.ToolVersion},
	}
	missing := make([]string, 0, len(required)+2)
	for _, field := range required {
		if strings.TrimSpace(field.value) == "" {
			missing = append(missing, field.name)
		}
	}
	if p.IngestedBy.IsZero() {
		missing = append(missing, "ingested by")
	}
	if p.IngestedAt.IsZero() {
		missing = append(missing, "ingested at")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: imported finding provenance is incomplete: missing %s",
			shared.ErrValidation, strings.Join(missing, ", "))
	}
	return nil
}

// Location is the normalized position an external result points at. Only repository-relative paths are
// accepted: a SARIF document is untrusted input, and an absolute path or a traversal would let a report
// point outside the scanned tree.
type Location struct {
	// Path is a repository-relative slash path, empty when the result has no physical location.
	Path string
	// StartLine and StartColumn are 1-based; zero means unspecified.
	StartLine   int
	StartColumn int
	// LogicalName is the tool's logical location (a fully-qualified symbol), kept when present.
	LogicalName string
}

// Validate enforces the repository-relative invariant HERE, in the domain, rather than leaving it to
// whichever ingester happens to produce the value.
//
// The SARIF ingester already normalizes and percent-decodes its input, but that is one producer. A
// second one — a native scanner importer, a backfill, a future API — would otherwise be able to persist
// `../../etc/passwd` through a store that only calls Validate. Decoding stays with the producer; the
// invariant lives with the type that promises it.
func (l Location) Validate() error {
	if l.StartLine < 0 || l.StartColumn < 0 {
		return fmt.Errorf("%w: imported finding location has a negative position", shared.ErrValidation)
	}
	if l.Path == "" {
		return nil
	}
	switch {
	case strings.IndexByte(l.Path, 0) >= 0, containsControl(l.Path):
		return fmt.Errorf("%w: imported finding path contains a control character", shared.ErrValidation)
	case strings.ContainsRune(l.Path, '\\'):
		return fmt.Errorf("%w: imported finding path %q is not slash-normalized", shared.ErrValidation, l.Path)
	case strings.HasPrefix(l.Path, "/"):
		return fmt.Errorf("%w: imported finding path %q is absolute", shared.ErrValidation, l.Path)
	case l.Path == "..", strings.HasPrefix(l.Path, "../"), strings.Contains(l.Path, "/../"), strings.HasSuffix(l.Path, "/.."):
		return fmt.Errorf("%w: imported finding path %q escapes the scanned tree", shared.ErrValidation, l.Path)
	case len(l.Path) >= 2 && l.Path[1] == ':':
		return fmt.Errorf("%w: imported finding path %q names a volume", shared.ErrValidation, l.Path)
	}
	return nil
}

func containsControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ImportedFinding is one third-party result under this system's governance.
type ImportedFinding struct {
	ID           shared.ID
	TenantID     shared.ID
	EngagementID shared.ID
	// FindingID links to a first-party finding this result agrees with, when deduplication matched one.
	FindingID shared.ID
	// Severity is the mapped severity. It is shared.SeverityUnknown when the source severity has no
	// documented mapping — NEVER a default of medium, which would silently invent a risk level.
	Severity shared.Severity
	// Title and Message are the tool's own description, kept verbatim for the reader.
	Title    string
	Message  string
	Location Location
	// Suppressed records that the source document marked this result suppressed. It is kept rather than
	// acted on: an external tool's suppression is information, not authority over this system's gate.
	Suppressed bool
	// Fingerprint is the tool's partial fingerprint, used for stable identity across re-scans.
	Fingerprint string
	Provenance  Provenance
	Audit       shared.Audit
}

// MaxBindingIdentityBytes bounds a derived identity. The components it is built from are themselves
// bounded by the SARIF reader (a rule id at 512 bytes, a path at 4096), so an unbounded identity would
// reach ~4.6 KB and overflow the 2704-byte limit of the btree index that enforces one binding per
// identity. Past this bound the identity is replaced by a digest of the same components, which is
// equally stable and equally unique.
const MaxBindingIdentityBytes = 1024

// BindingScope and BindingExternalIdentity name this observation ACROSS imports, which is what an
// approved binding has to be keyed on (#1184). The row id cannot serve: re-importing a report mints new
// rows, and a decision a person made must survive that. Neither can the storage idempotency key, which
// includes the source document digest and therefore changes whenever the report does.
//
// The scope is the producing tool.
func (f ImportedFinding) BindingScope() string {
	return strings.TrimSpace(f.Provenance.ToolName)
}

// BindingExternalIdentity returns the cross-import identity of this observation, or the empty string when
// the result cannot be addressed by a decision at all.
//
// A tool that supplies a partial fingerprint is taken at its word: that value is exactly the tool's
// assertion of "this is the same result as last time". Note what that means for trust: whoever can post a
// report chooses the fingerprint, so an approval follows the tool's claim of identity. It is the same
// permission that can record a binding directly, so this widens no authority, but it does mean a binding
// is only as precise as the identity its producer asserts.
//
// Without a fingerprint the identity is derived, and it has to discriminate results that a reviewer would
// never call the same one. Rule and location alone do not: two secrets on one line, or two different
// messages from one rule at one place, would collapse into a single identity and one person's decision
// would mark the other as approved without anyone looking at it. The column and a digest of the result's
// own words are therefore part of the identity. They are stable across a re-import of the same result and
// differ between results a reviewer would read differently.
//
// Every component is escaped before it is joined, so a rule id containing the separator cannot forge the
// identity of a different result.
func (f ImportedFinding) BindingExternalIdentity() string {
	if fingerprint := strings.TrimSpace(f.Fingerprint); fingerprint != "" {
		return boundBindingIdentity("fingerprint:" + escapeIdentityPart(fingerprint))
	}
	rule := strings.TrimSpace(f.Provenance.RuleID)
	location := strings.TrimSpace(f.Location.Path)
	if location == "" {
		location = strings.TrimSpace(f.Location.LogicalName)
	}
	if rule == "" || location == "" {
		// A result with no rule, or with no location at all, has nothing that distinguishes it from the
		// next result of its kind. Binding it would attach a decision to a key that other results share.
		return ""
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(f.Title) + "\x00" + strings.TrimSpace(f.Message)))
	return boundBindingIdentity("rule:" + escapeIdentityPart(rule) +
		"@" + escapeIdentityPart(location) +
		":" + strconv.Itoa(f.Location.StartLine) +
		":" + strconv.Itoa(f.Location.StartColumn) +
		"#" + hex.EncodeToString(digest[:6]))
}

// escapeIdentityPart makes a component unambiguous inside a joined identity by percent-encoding the
// separators and the escape character itself. Without it `rule:"A@B"` at `c.go` and `rule:"A"` at
// `B@c.go` produce one string, so a decision about one result would address the other.
func escapeIdentityPart(part string) string {
	if !strings.ContainsAny(part, "%@:#") {
		return part
	}
	var b strings.Builder
	b.Grow(len(part) + 8)
	for i := 0; i < len(part); i++ {
		switch c := part[i]; c {
		case '%':
			b.WriteString("%25")
		case '@':
			b.WriteString("%40")
		case ':':
			b.WriteString("%3A")
		case '#':
			b.WriteString("%23")
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// boundBindingIdentity keeps an identity inside MaxBindingIdentityBytes, replacing an over-long one with
// a digest of itself. The digest is derived from the escaped form, so it is as unique as what it replaces.
func boundBindingIdentity(identity string) string {
	if len(identity) <= MaxBindingIdentityBytes {
		return identity
	}
	sum := sha256.Sum256([]byte(identity))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// External reports that this finding came from another tool. It exists so every surface that renders a
// finding has one obvious predicate to branch on rather than inferring it.
func (ImportedFinding) External() bool { return true }

// CanSelfPromote reports whether an imported finding may promote itself through the judgment gate.
//
// It is always false. An external tool's confidence is not a distinct verifier's sealed verdict, so an
// imported result can only ever be evidence a human or a verifier weighs — never its own justification.
func (ImportedFinding) CanSelfPromote() bool { return false }

// Validate checks the invariants that must hold before a finding is stored.
func (f ImportedFinding) Validate() error {
	if f.EngagementID.IsZero() {
		return fmt.Errorf("%w: imported finding needs an engagement", shared.ErrValidation)
	}
	if f.TenantID.IsZero() {
		return fmt.Errorf("%w: imported finding needs a tenant", shared.ErrValidation)
	}
	if err := f.Provenance.Validate(); err != nil {
		return err
	}
	if err := f.Location.Validate(); err != nil {
		return err
	}
	if !validSeverity(f.Severity) {
		return fmt.Errorf("%w: imported finding severity %q is not a known severity", shared.ErrValidation, f.Severity)
	}
	return nil
}

// IdempotencyKey is the identity that makes a re-ingest a no-op: one finding per tenant, engagement,
// source document, rule and location.
//
// It lives in the domain because every store must agree on it. A store that computed its own would drift
// from the persistent unique constraint, and the two would then disagree about what "already ingested"
// means — one duplicating what the other deduplicates.
//
// The NUL separator cannot be forged from within a field: the join always emits exactly six separators,
// so an embedded NUL changes the count rather than shifting a boundary.
func IdempotencyKey(f ImportedFinding) string {
	return strings.Join([]string{
		f.TenantID.String(),
		f.EngagementID.String(),
		f.Provenance.SourceDigest,
		f.Provenance.RuleID,
		f.Location.Path,
		strings.TrimSpace(f.Location.LogicalName),
		strconv.Itoa(f.Location.StartLine),
	}, "\x00")
}

func validSeverity(s shared.Severity) bool {
	switch s {
	case shared.SeverityCritical, shared.SeverityHigh, shared.SeverityMedium,
		shared.SeverityLow, shared.SeverityInfo, shared.SeverityUnknown:
		return true
	}
	return false
}

// RefusalReason is a typed explanation for a result that was NOT ingested.
//
// Refusals are returned as a list rather than a count, because a silent refusal is indistinguishable
// from a clean ingest — the caller must be able to see exactly what was dropped and why.
type RefusalReason struct {
	// RunIndex and ResultIndex locate the refused result in the source document.
	RunIndex    int
	ResultIndex int
	// Code is the machine-readable refusal class.
	Code RefusalCode
	// Detail is a short human-readable explanation that never quotes document content.
	Detail string
}

// RefusalCode enumerates why a result can be refused.
type RefusalCode string

const (
	RefusalNoProvenance    RefusalCode = "no-provenance"
	RefusalInvalidLocation RefusalCode = "invalid-location"
	RefusalUnsupportedURI  RefusalCode = "unsupported-uri-scheme"
	// RefusalUnsupportedURIBase is a location expressed relative to a base directory that is not the
	// root of the scanned tree. Such a path is NOT repository-relative, so storing it as one would
	// relabel a file outside the tree as a file inside it.
	RefusalUnsupportedURIBase RefusalCode = "unsupported-uri-base"
	RefusalPathTraversal      RefusalCode = "path-traversal"
	RefusalAbsolutePath       RefusalCode = "absolute-path"
	RefusalMalformedResult    RefusalCode = "malformed-result"
	// RefusalTooManyElements is a result declaring more repeated elements (locations, fingerprints,
	// tags) than can be held safely. It is a COUNT bound, not a traversal limit: this ingester never
	// follows a related location, so a cycle among them cannot be entered in the first place.
	RefusalTooManyElements RefusalCode = "too-many-elements"
)

// Valid reports whether c is a known refusal code.
func (c RefusalCode) Valid() bool {
	switch c {
	case RefusalNoProvenance, RefusalInvalidLocation, RefusalUnsupportedURI, RefusalUnsupportedURIBase,
		RefusalPathTraversal, RefusalAbsolutePath, RefusalMalformedResult, RefusalTooManyElements:
		return true
	}
	return false
}

// CoverageIssue records a limitation of the ingest itself, distinct from a refused result.
type CoverageIssue struct {
	Detail string
}
