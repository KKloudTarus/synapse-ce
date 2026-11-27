// Package audit makes the audit trail tamper-evident: each entry's Hash covers its
// content AND the previous entry's Hash, exactly like the evidence chain (golden
// rule 6). Any later edit, insertion, or deletion breaks the chain and is detectable
// by re-verification. The timestamp is truncated to microseconds before hashing so a
// write-time hash matches one recomputed from a stored row (Postgres keeps µs).
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// ErrChainBroken is returned when the audit chain fails verification.
var ErrChainBroken = errors.New("audit chain broken")

const sep = "\x1f" // field terminator of the legacy preimage; see HashSchemeLegacy

// Hash schemes. A scheme fixes how a record's fields become the bytes that are hashed. It is
// stored with every record, and verification recomputes each record under the scheme it was
// written with, so a chain may hold records of both schemes and still verify end to end.
const (
	// HashSchemeLegacy terminates each field with a unit separator. Field contents are neither
	// escaped nor length-prefixed, so two different records can share a preimage: metadata
	// {"a=b": "c"} and {"a": "b=c"} both write "a=b=c". Records written under it keep verifying
	// under it after writers move to HashSchemeFramed.
	HashSchemeLegacy = 1
	// HashSchemeFramed prefixes the preimage with a domain tag and writes every field as its byte
	// length followed by its bytes, so the preimage decodes back to exactly one record.
	HashSchemeFramed = 2
	// CurrentHashScheme is the scheme every new record is written with. v0.3.0 taught every reader the
	// scheme while still writing legacy, so a framed row written during a rolling deploy from v0.3.0 reads
	// correctly on both binaries. A binary older than v0.3.0 recomputes every row as legacy and would read
	// a framed row as tampered, so upgrade through v0.3.0.
	CurrentHashScheme = HashSchemeFramed
)

// framedDomain separates audit preimages from every other framed preimage in the product.
const framedDomain = "synapse-audit-record:v2"

// Record is one link in the audit hash chain. It mirrors the audit entry's fields
// plus the chain hashes (kept out of the use-case AuditEntry's hashed content).
// Scheme is the HashScheme the record was written with; zero reads as HashSchemeLegacy,
// because records written before the scheme existed carry none.
type Record struct {
	Actor        string
	Action       string
	Target       string
	Metadata     map[string]string
	At           time.Time
	Hash         string
	PreviousHash string
	Scheme       int
}

// ComputeHash returns the chain hash binding this record's content to previousHash under
// scheme. Deterministic: metadata keys are sorted and the timestamp truncated to µs. An unknown
// scheme returns "", which no stored hash equals, so a record claiming one never verifies.
func ComputeHash(scheme int, previousHash, actor, action, target string, metadata map[string]string, at time.Time) string {
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	stamp := at.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)

	h := sha256.New()
	switch scheme {
	case 0, HashSchemeLegacy:
		write := func(s string) { h.Write([]byte(s)); h.Write([]byte(sep)) }
		write(previousHash)
		write(actor)
		write(action)
		write(target)
		for _, k := range keys {
			write(k + "=" + metadata[k])
		}
		write(stamp)
	case HashSchemeFramed:
		field := func(s string) {
			var n [8]byte
			binary.BigEndian.PutUint64(n[:], uint64(len(s)))
			h.Write(n[:])
			h.Write([]byte(s))
		}
		field(framedDomain)
		field(previousHash)
		field(actor)
		field(action)
		field(target)
		var count [8]byte
		binary.BigEndian.PutUint64(count[:], uint64(len(keys)))
		h.Write(count[:])
		for _, k := range keys {
			field(k)
			field(metadata[k])
		}
		field(stamp)
	default:
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain checks that items form an unbroken hash chain in order: each item's
// PreviousHash equals the prior item's Hash, and each Hash recomputes from its own
// content. Returns ErrChainBroken at the first break.
func VerifyChain(items []Record) error {
	prev := ""
	for i, r := range items {
		if r.PreviousHash != prev {
			return fmt.Errorf("%w: entry %d previous_hash does not match the prior entry", ErrChainBroken, i)
		}
		// An unknown scheme computes "", which must not match a link stored with an empty hash.
		if want := ComputeHash(r.Scheme, prev, r.Actor, r.Action, r.Target, r.Metadata, r.At); want == "" || r.Hash != want {
			return fmt.Errorf("%w: entry %d hash does not match its content (tampered)", ErrChainBroken, i)
		}
		prev = r.Hash
	}
	return nil
}

// Report is the audit chain's verification status. Verified counts the chained
// records; Unchained counts leading legacy records written before the chain feature
// shipped (no Hash) – they are reported honestly, not silently treated as intact.
type Report struct {
	Intact    bool   `json:"intact"`
	Verified  int    `json:"verified"`
	Unchained int    `json:"unchained"`
	Head      string `json:"head"`
	Error     string `json:"error,omitempty"`
}

// Verify builds a Report from an ordered (oldest-first) slice of records. Leading
// records with no Hash predate the chain (an upgraded deployment) and are counted as
// Unchained, not verified; the chain is then checked from the first hashed record
// (whose PreviousHash MUST be "", the genesis link). An empty hash AFTER the chain
// begins is a break, not a legacy row.
//
// Threat model: this detects in-application tampering, accidental edits, and the
// deletion or blanking of ANY row that leaves a verifiable suffix – including an
// attempt to blank a leading prefix so it is mistaken for legacy, because the
// surviving suffix's first record then has a non-empty PreviousHash and fails the
// genesis check. What an unanchored hash chain CANNOT detect on its own is a
// privileged operator who reforges the whole chain (blanks rows, then recomputes
// every subsequent Hash with ComputeHash) or erases it entirely. Closing that gap
// requires an external anchor – signing the audit head (as evidence heads are signed,
// WS4) or an RFC-3161 timestamp (ports.TimestampAuthority, wired via the audit service's
// SetTimestamper). A non-zero Unchained count must always be surfaced, never treated as benign.
func Verify(items []Record) Report {
	start := 0
	for start < len(items) && items[start].Hash == "" {
		start++
	}
	chained := items[start:]
	rep := Report{Intact: true, Verified: len(chained), Unchained: start}
	if len(chained) > 0 {
		rep.Head = chained[len(chained)-1].Hash
	}
	if err := VerifyChain(chained); err != nil {
		rep.Intact = false
		rep.Error = err.Error()
	}
	return rep
}

// maxReportedBrokenChains bounds how many broken chains one report names. The message is stored and
// rendered, so a database whose chains are all broken must not produce an error field that grows with
// the tenant count.
const maxReportedBrokenChains = 8

// VerifyChains builds one Report over several INDEPENDENT chains.
//
// The audit log holds more than one chain. The legacy rows written before tenancy form a single
// global chain; every row written since is linked within its own tenant, which the partial unique
// index audit_chain_link_v2_uniq (tenant_id, previous_hash) is what enforces. Each of those starts
// at an empty previous_hash, so concatenating them and checking the result as one chain reports a
// break at the first row of the second tenant. It is not a break: it is the next chain beginning.
//
// The returned Report is intact only when every chain is. Verified and Unchained are summed across
// them, and Head is left empty, because several chains have several heads and reporting one of them
// would be arbitrary. Error names the chain that broke, so an operator knows where to look.
func VerifyChains(chains map[string][]Record) Report {
	names := make([]string, 0, len(chains))
	for name := range chains {
		names = append(names, name)
	}
	sort.Strings(names)

	out := Report{Intact: true}
	broken := make([]string, 0, len(names))
	for _, name := range names {
		rep := Verify(chains[name])
		out.Verified += rep.Verified
		out.Unchained += rep.Unchained
		if rep.Intact {
			continue
		}
		out.Intact = false
		// Every broken chain is named, not only the first. One chain breaking says nothing about the
		// others, and an operator told about the earliest one alone would repair it and re-run into the
		// next. The list is bounded because the message is stored and rendered.
		switch {
		case len(broken) < maxReportedBrokenChains:
			broken = append(broken, name+": "+rep.Error)
		case len(broken) == maxReportedBrokenChains:
			broken = append(broken, "further chains are broken; re-run after repairing these")
		}
	}
	out.Error = strings.Join(broken, "; ")
	if len(chains) == 1 {
		for _, only := range chains {
			out.Head = Verify(only).Head
		}
	}
	return out
}

// ensure shared is used (sentinel parity with other domains; reserved for future
// validation helpers).
var _ = shared.ErrValidation
