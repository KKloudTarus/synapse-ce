package jarhash

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no cgo; matches CGO_ENABLED=0 builds)

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// OfflineResolver recovers a shaded/metadata-less JAR's Maven coordinate from its SHA-1 against a LOCAL
// SQLite index in the trivy-java-db schema. It removes the online rate-limit exposure
// and works air-gapped. The operator supplies the DB (e.g. `oras pull ghcr.io/aquasecurity/trivy-java-db:1`,
// Apache-2.0, or a self-built index of Maven Central `.jar.sha1` sidecars); Synapse only READS it. The DB
// is opened read-only for the process lifetime. Best-effort: a miss / DB error leaves the component
// unchanged and never fails the scan. Compose it before the online resolver via Chain (offline first).
type OfflineResolver struct {
	db *sql.DB
}

// trivy-java-db (schema v1): a JAR's whole-file SHA-1 (raw 20-byte BLOB, UNIQUE) → (groupId, artifactId,
// version). Two tables joined on the artifact id.
const lookupSQL = `SELECT a.group_id, a.artifact_id, i.version
FROM indices i JOIN artifacts a ON i.artifact_id = a.id
WHERE i.sha1 = ?
ORDER BY a.group_id, a.artifact_id, i.version
LIMIT 1`

// NewOffline opens the trivy-java-db-format SQLite file at dbPath read-only and validates its schema.
// An unreadable file or an unexpected schema is a hard error (the caller logs + falls back to online-only).
func NewOffline(dbPath string) (*OfflineResolver, error) {
	if strings.TrimSpace(dbPath) == "" {
		return nil, fmt.Errorf("jarhash offline: empty db path")
	}
	// The DSN is `file:<path>?mode=ro`; a '?' in the path would leak into the DSN query and could override
	// mode=ro (defense-in-depth – the path is trusted operator config, but keep the read-only guarantee
	// textual-injection-proof). Reject it, and require a regular file (a clear error, not a driver error).
	if strings.ContainsAny(dbPath, "?#") {
		return nil, fmt.Errorf("jarhash offline: db path %q must not contain '?' or '#'", dbPath)
	}
	if fi, err := os.Stat(dbPath); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("jarhash offline: db path %q is not a readable file: %w", dbPath, err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("jarhash offline: open %q: %w", dbPath, err)
	}
	db.SetMaxOpenConns(4) // bounded: one shared resolver serves concurrent engagements (cross-scan, not per-component)
	// Validate the schema up front (a wrong file must fail loudly at wiring, not silently at every query).
	var one int
	if err := db.QueryRow(`SELECT 1 FROM indices JOIN artifacts ON indices.artifact_id = artifacts.id LIMIT 1`).Scan(&one); err != nil && !errors.Is(err, sql.ErrNoRows) {
		_ = db.Close()
		return nil, fmt.Errorf("jarhash offline: %q is not a trivy-java-db schema: %w", dbPath, err)
	}
	return &OfflineResolver{db: db}, nil
}

var _ ports.JarHashResolver = (*OfflineResolver)(nil)

// Close releases the DB handle.
func (r *OfflineResolver) Close() error {
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}

// Resolve fills the coordinate of each unresolved component from the local index, correcting the PURL in
// place. Returns the number recovered. Best-effort: a miss / DB error is a per-component no-op.
func (r *OfflineResolver) Resolve(ctx context.Context, comps []sbom.Component) int {
	if r.db == nil {
		return 0
	}
	// A local SQLite lookup has no rate limit, so – unlike the online Resolver – this deliberately does NOT
	// group by SHA-1; N components sharing a hash just do N cheap indexed reads (grouping would add
	// complexity for negligible gain).
	recovered := 0
	for i := range comps {
		if ctx.Err() != nil {
			break
		}
		if !needsLookup(comps[i]) {
			continue
		}
		blob, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(comps[i].SHA1)))
		if err != nil {
			continue // not valid hex – nothing to look up
		}
		var g, a, v string
		if err := r.db.QueryRowContext(ctx, lookupSQL, blob).Scan(&g, &a, &v); err != nil {
			continue // miss (sql.ErrNoRows) or a transient DB error → leave unchanged
		}
		// The DB is operator-supplied data; still validate before it becomes a PURL / advisory-match key,
		// mirroring the online path (untrusted-input hardening).
		if !validGA(g) || !validGA(a) || !validVersion(v) {
			continue
		}
		applyCoord(&comps[i], coord{group: g, artifact: a, version: v})
		recovered++
	}
	return recovered
}

// Chain runs several JarHashResolvers in order over the SAME component slice; each successive resolver
// only sees components the earlier ones left unresolved (needsLookup skips a now-fixed pkg:maven coord),
// so composing offline-then-online gives "local index first, online fallback for its misses".
type Chain struct{ resolvers []ports.JarHashResolver }

// NewChain composes resolvers, dropping nils. Order matters: put the offline DB before the online client.
func NewChain(rs ...ports.JarHashResolver) *Chain {
	out := make([]ports.JarHashResolver, 0, len(rs))
	for _, r := range rs {
		if r != nil {
			out = append(out, r)
		}
	}
	return &Chain{resolvers: out}
}

var _ ports.JarHashResolver = (*Chain)(nil)

func (c *Chain) Resolve(ctx context.Context, comps []sbom.Component) int {
	total := 0
	for _, r := range c.resolvers {
		total += r.Resolve(ctx, comps)
	}
	return total
}
