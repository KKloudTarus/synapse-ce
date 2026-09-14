package vex

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

// StoredStatement is one persisted VEX assertion for an engagement, retained so it can be RE-APPLIED after a
// rescan overwrites the engagement's findings back to open. A raw apply-and-forget import would be lost on the
// next scan; persisting the assertion lets the pipeline re-evaluate it against the fresh finding set. It
// carries the faithful Statement plus provenance (who ingested it, when).
type StoredStatement struct {
	Advisory   string    // Statement.Vulnerability, denormalized for querying/audit
	Digest     string    // stable content digest of the Statement, for idempotent persistence
	Statement  Statement // the faithful assertion, re-applied verbatim (same match semantics as import)
	Actor      string    // the identity that ingested it
	IngestedAt time.Time // when it was ingested (UTC)
}

// StatementDigest is a stable content hash of a Statement, with products sorted so ordering never changes the
// digest. Re-importing an identical assertion is therefore idempotent (same digest), while any change to the
// advisory, status, justification, or product set yields a distinct digest (a new, separately-retained row).
func StatementDigest(s Statement) string {
	products := append([]string(nil), s.Products...)
	sort.Strings(products)
	h := sha256.New()
	write := func(v string) {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	write(s.Vulnerability)
	write(s.Status)
	write(s.Justification)
	for _, p := range products {
		write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// NewStoredStatement builds a StoredStatement with its digest computed and its ingest time normalized to UTC.
func NewStoredStatement(s Statement, actor string, at time.Time) StoredStatement {
	return StoredStatement{
		Advisory:   s.Vulnerability,
		Digest:     StatementDigest(s),
		Statement:  s,
		Actor:      actor,
		IngestedAt: at.UTC(),
	}
}
