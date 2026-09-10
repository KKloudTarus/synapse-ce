package advisory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	MaxRawPayloadBytes      = 4 << 20
	MaxRawReferenceLen      = 1024
	MaxMaterializationBatch = 1024
)

// Status is the canonical lifecycle state of an advisory. Rejected and withdrawn
// advisories remain queryable; neither state means delete.
type Status string

const (
	StatusActive    Status = "active"
	StatusRejected  Status = "rejected"
	StatusWithdrawn Status = "withdrawn"
)

func (s Status) Valid() bool {
	return s == StatusActive || s == StatusRejected || s == StatusWithdrawn
}

// Observation is one provider's normalized current view of an advisory. Optional
// enrichment values use pointers so a sparse provider cannot erase a field it did
// not publish.
type Observation struct {
	SourceType         string
	SourceID           string
	RecordID           string
	Advisory           Advisory
	Status             Status
	PublishedAt        time.Time
	ModifiedAt         time.Time
	KEV                *bool
	EPSS               *float64
	EPSSPercentile     *float64
	PublicExploit      *bool
	ActiveExploitation *bool
	// SignatureVerified records that this observation's source document carried a valid provider OpenPGP
	// signature that was verified before ingest (D1.8). It is persisted in the observation's normalized
	// payload as the authenticity audit trail. omitempty: a provider without signature verification (most
	// feeds) simply omits it. Because verification is fail-closed, an ingested observation is never marked
	// with a failed verification; the field is set true only on a document that verified.
	SignatureVerified bool `json:",omitempty"`
}

// ObservationRecord is the bounded persistence envelope for one provider record.
// RawPayload is retained only for controlled replay/debugging; normalized data is
// what materialization and matching consume.
type ObservationRecord struct {
	Observation  Observation
	RawPayload   []byte
	RawReference string
	SyncRunID    string
	ObservedAt   time.Time
}

func ValidateBatch(records []ObservationRecord) error {
	if len(records) == 0 {
		return fmt.Errorf("advisory observation batch is empty")
	}
	if len(records) > MaxMaterializationBatch {
		return fmt.Errorf("advisory observation batch exceeds %d records", MaxMaterializationBatch)
	}
	return nil
}

// Normalize validates and canonicalizes provider-owned fields before persistence.
func (r ObservationRecord) Normalize() (ObservationRecord, error) {
	r.Observation.SourceType = strings.ToLower(strings.TrimSpace(r.Observation.SourceType))
	r.Observation.SourceID = strings.TrimSpace(r.Observation.SourceID)
	r.Observation.RecordID = strings.TrimSpace(r.Observation.RecordID)
	r.Observation.Advisory.ID = normalizeID(r.Observation.Advisory.ID)
	r.Observation.Advisory.Aliases = uniqueSortedIDs(r.Observation.Advisory.Aliases, r.Observation.Advisory.ID)
	r.Observation.Advisory.Summary = strings.TrimSpace(r.Observation.Advisory.Summary)
	r.Observation.Advisory.Affected = mergeAffected([]Observation{{Advisory: r.Observation.Advisory}})
	r.Observation.Advisory.CPEs = mergeCPEs([]Observation{{Advisory: r.Observation.Advisory}})
	r.Observation.Status = normalizeStatus(r.Observation.Status)
	r.Observation.PublishedAt = r.Observation.PublishedAt.UTC()
	r.Observation.ModifiedAt = r.Observation.ModifiedAt.UTC()
	r.RawReference = strings.TrimSpace(r.RawReference)
	if r.ObservedAt.IsZero() {
		r.ObservedAt = time.Now().UTC()
	} else {
		r.ObservedAt = r.ObservedAt.UTC()
	}
	if r.Observation.SourceID == "" || r.Observation.RecordID == "" || r.Observation.Advisory.ID == "" {
		return ObservationRecord{}, fmt.Errorf("observation source, record, and advisory ids are required")
	}
	if !r.Observation.Status.Valid() {
		return ObservationRecord{}, fmt.Errorf("invalid advisory observation status %q", r.Observation.Status)
	}
	if len(r.RawPayload) > MaxRawPayloadBytes {
		return ObservationRecord{}, fmt.Errorf("raw advisory payload exceeds %d bytes", MaxRawPayloadBytes)
	}
	if len(r.RawReference) > MaxRawReferenceLen {
		return ObservationRecord{}, fmt.Errorf("raw advisory reference exceeds %d characters", MaxRawReferenceLen)
	}
	r.RawPayload = append([]byte(nil), r.RawPayload...)
	return r, nil
}

func normalizeStatus(status Status) Status {
	if status == "" {
		return StatusActive
	}
	return status
}

// IdentityIDs returns the normalized primary id and aliases used for matching
// observations belonging to the same canonical advisory.
func (r ObservationRecord) IdentityIDs() []string {
	ids := append([]string{r.Observation.Advisory.ID}, r.Observation.Advisory.Aliases...)
	return uniqueSortedIDs(ids, "")
}

// ContentHash returns a stable SHA-256 hash of the normalized provider view.
func (r ObservationRecord) ContentHash() (string, error) {
	normalized, err := r.Normalize()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(normalized.Observation)
	if err != nil {
		return "", fmt.Errorf("marshal advisory observation: %w", err)
	}
	hash := sha256.Sum256(payload)
	return hex.EncodeToString(hash[:]), nil
}

// Canonical is the deterministic materialized view built from current provider
// observations. Advisory remains the existing scan-facing projection.
type Canonical struct {
	Advisory           Advisory
	Status             Status
	PublishedAt        time.Time
	ModifiedAt         time.Time
	KEV                *bool
	EPSS               *float64
	EPSSPercentile     *float64
	PublicExploit      *bool
	ActiveExploitation *bool
	Sources            []string
}

// Project returns the SCAN-FACING Advisory projection for this canonical: the base Advisory with the
// canonical's status-derived Withdrawn flag and its merged exploitation-risk signals (KEV / EPSS / EPSS
// percentile / public exploit) copied in. Both the Postgres and in-memory materializers project through
// this, so their scan-time reads (ByPackage/ByCPE) carry the same fields and an OFFLINE scan sees the same
// retraction and exploitation-priority data regardless of the store. A nil risk pointer projects as the
// zero value (unknown = "not known exploited" / EPSS 0), never a false positive risk boost.
func (c Canonical) Project() Advisory {
	a := c.Advisory
	a.Withdrawn = c.Status == StatusWithdrawn || c.Status == StatusRejected
	a.KEV = derefBool(c.KEV)
	a.PublicExploit = derefBool(c.PublicExploit)
	a.EPSS = derefFloat(c.EPSS)
	a.EPSSPercentile = derefFloat(c.EPSSPercentile)
	return a
}

func derefBool(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

func derefFloat(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// MaterializationResult describes the committed canonical transition.
type MaterializationResult struct {
	Canonical       Canonical
	Revision        int64
	ContentHash     string
	ChangedFields   []ChangedField
	CreatedRevision bool
}

// ChangedField names one independently explainable canonical change.
type ChangedField string

const (
	ChangedIdentity       ChangedField = "identity"
	ChangedAliases        ChangedField = "aliases"
	ChangedSummary        ChangedField = "summary"
	ChangedCVSS           ChangedField = "cvss"
	ChangedDates          ChangedField = "dates"
	ChangedAffected       ChangedField = "affected"
	ChangedStatus         ChangedField = "status"
	ChangedExploitability ChangedField = "exploitability"
	ChangedSources        ChangedField = "sources"
)
