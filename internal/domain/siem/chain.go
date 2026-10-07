package siem

import (
	"strconv"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/audit"
)

// VerifyAuditContent checks one forward page against the committed cursor.
//
// metadata[i] is the exact map the audit writer hashed. It is a verification
// input, not an export. Row ids are not required to be contiguous: other
// tenants and rolled-back inserts leave holes, and those holes are not
// missing records. A v2 row that does not link to the cursor is a break.
//
// A zero cursor accepts only a genesis link. A first v2 row whose previous
// hash is not empty stops the partition instead of pretending the legacy
// chain was verified. Legacy v1 presence is reported on the anchor.
func VerifyAuditContent(cursor Position, rows []AuditFact, metadata []map[string]string, anchor AuditAnchor) ([]AuditFact, Problem) {
	if len(metadata) != len(rows) {
		return nil, Problem{Kind: "broken", Message: "audit metadata snapshot does not match the page"}
	}
	if cursor.Source != SourceAudit && cursor.Source != "" {
		return nil, Problem{Kind: "broken", Message: "audit page was checked against a different source"}
	}
	if !cursor.Zero() {
		if !anchor.CursorFound || anchor.CursorHash != cursor.AuditHash || anchor.CursorID != cursor.AuditID {
			return nil, Problem{Kind: "broken", Message: "stored audit cursor no longer matches the source row"}
		}
	}
	if len(rows) == 0 {
		if cursor.Zero() {
			if anchor.HeadID == 0 {
				return nil, Problem{}
			}
			return nil, Problem{Kind: "gap", Message: "audit head exists but the first page was empty"}
		}
		if anchor.HeadID == cursor.AuditID && anchor.HeadHash == cursor.AuditHash {
			return nil, Problem{}
		}
		return nil, Problem{Kind: "gap", Message: "audit head moved without a readable successor"}
	}
	prevHash := ""
	if !cursor.Zero() {
		prevHash = cursor.AuditHash
	}
	accepted := make([]AuditFact, 0, len(rows))
	for i, row := range rows {
		if row.HashVersion != 2 || row.ID <= 0 || row.Hash == "" {
			return accepted, Problem{Kind: "broken", Message: "audit row is not a v2 chain link"}
		}
		if cursor.Zero() && i == 0 && row.PreviousHash != "" {
			return nil, Problem{Kind: "broken", Message: "v2 audit chain does not start at genesis; legacy history is not attached"}
		}
		if row.PreviousHash != prevHash {
			return accepted, Problem{Kind: "broken", Message: "audit previous hash does not match the prior link"}
		}
		at := time.UnixMicro(row.AtUnixMicro).UTC()
		want := audit.ComputeHash(prevHash, row.Actor, row.Action, row.Target, metadata[i], at)
		if want != row.Hash {
			return accepted, Problem{Kind: "broken", Message: "audit content hash does not match the stored link"}
		}
		if !cursor.Zero() && row.ID <= cursor.AuditID {
			return accepted, Problem{Kind: "broken", Message: "audit page moved backwards"}
		}
		accepted = append(accepted, AuditWithMetadata(row, metadata[i]))
		prevHash = row.Hash
	}
	return accepted, Problem{}
}

// VerifyIncidentPage requires a contiguous capture sequence. The counter and
// the insert commit together, so a missing sequence is a lost row, not a
// legal hole the way an audit id hole is.
func VerifyIncidentPage(cursor Position, rows []IncidentFact) ([]IncidentFact, Problem) {
	next := cursor.StreamSeq + 1
	if cursor.Zero() {
		next = 1
	}
	accepted := make([]IncidentFact, 0, len(rows))
	for _, row := range rows {
		if row.StreamSeq != next {
			return accepted, Problem{Kind: "gap", Message: "incident capture sequence jumped from " + strconv.FormatInt(next-1, 10) + " to " + strconv.FormatInt(row.StreamSeq, 10)}
		}
		if row.IncidentID == "" || row.EventSeq <= 0 {
			return accepted, Problem{Kind: "broken", Message: "incident capture row has no source identity"}
		}
		accepted = append(accepted, row)
		next++
	}
	return accepted, Problem{}
}
