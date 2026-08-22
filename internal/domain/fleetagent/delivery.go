package fleetagent

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/detection"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/domain/telemetry"
)

// Delivery contract (#609, A0.4). The agent ships security signals to the control plane under an explicit,
// modest guarantee — NOT exactly-once:
//
//	at-least-once delivery + idempotent ingest + a durable agent spool + a monotonic sequence per
//	(stream, incarnation) + a highest-contiguous ACK + explicit, queryable gaps.
//
// This file is the CONTRACT: the identity, ordering, de-duplication, and gap primitives both sides agree
// on. The agent-side write-ahead spool (fsync/eviction/backoff/resume) is A2; the ingest+ACK transport is
// A3. Both consume these types, so the safety properties are defined and tested here, once, independent of
// any wire format or disk layout.

// DeliveryPriority is the spool/delivery priority class of a signal. The agent's durable spool drains by
// class so the signals that matter most for a live engagement survive back-pressure and disk pressure
// first. The ladder is the contract; assigning a concrete signal to a class is the producer's job (A2).
type DeliveryPriority int

const (
	// PriorityP0 — response-verification results, coverage/honesty, and sensor-health. Losing these would
	// make the platform lie about what it did or saw, so they drain first and are evicted last.
	PriorityP0 DeliveryPriority = iota
	// PriorityP1 — confirmed detections.
	PriorityP1
	// PriorityP2 — privilege changes and critical-file events.
	PriorityP2
	// PriorityP3 — background process/network telemetry (the highest-volume, most-sheddable stream).
	PriorityP3
)

// Valid reports whether p is one of the defined priority classes.
func (p DeliveryPriority) Valid() bool { return p >= PriorityP0 && p <= PriorityP3 }

// String renders the priority as its stable wire label (P0..P3).
func (p DeliveryPriority) String() string {
	switch p {
	case PriorityP0:
		return "P0"
	case PriorityP1:
		return "P1"
	case PriorityP2:
		return "P2"
	case PriorityP3:
		return "P3"
	default:
		return "P?"
	}
}

// TelemetryPriority assigns canonical raw telemetry to the A2 priority ladder. Privilege transitions and
// sensitive-file observations are never-shed P2; high-volume process/network observations are evictable
// P3. P0 and P1 are reserved for coverage/verification and confirmed detections respectively.
func TelemetryPriority(class detection.Class) (DeliveryPriority, error) {
	if !class.Valid() {
		return PriorityP3, fmt.Errorf("%w: unknown telemetry class %q", shared.ErrValidation, class)
	}
	if telemetry.MustNotShed(class) {
		return PriorityP2, nil
	}
	return PriorityP3, nil
}

// SessionID identifies one agent run/enrolment session; BootID identifies one host boot. Both are opaque
// (typically random) — they are recorded for attribution and to detect corruption, but ordering is decided
// by the Epoch, because random ids cannot be compared. A reinstall changes the Session; a reboot changes
// the Boot; either resets the per-stream Sequence, and the agent signals that reset by advancing Epoch.
type SessionID string
type BootID string

// StreamPosition is where an agent is in one priority stream. Sequence is monotonic within an INCARNATION
// (Epoch); on a reboot/reinstall/spool-loss the agent starts a new incarnation — Epoch increments and
// Sequence restarts at 1. Carrying a monotonic Epoch (not just the opaque Session/Boot) is what lets the
// control plane tell a legitimate reset-to-1 apart from a replay of an old sequence: a higher Epoch is a
// new incarnation, never a replay.
type StreamPosition struct {
	Priority DeliveryPriority
	Epoch    uint64 // incarnation counter; increments on every Sequence reset (reboot/reinstall/spool-loss)
	Sequence uint64 // monotonic within (Priority, Epoch); restarts at 1 when Epoch increments
	Session  SessionID
	Boot     BootID
}

// Validate checks a position is well-formed: a real priority, an incarnation and sequence that both start
// at 1, and non-empty session/boot ids (so every accepted signal is attributable to a concrete run+boot).
func (p StreamPosition) Validate() error {
	if !p.Priority.Valid() {
		return fmt.Errorf("%w: unknown delivery priority %d", shared.ErrValidation, int(p.Priority))
	}
	if p.Epoch == 0 {
		return fmt.Errorf("%w: stream epoch must be >= 1 (0 is reserved for 'no incarnation yet')", shared.ErrValidation)
	}
	if p.Sequence == 0 {
		return fmt.Errorf("%w: stream sequence must be >= 1 (0 is reserved for 'no batch yet')", shared.ErrValidation)
	}
	if p.Session == "" {
		return fmt.Errorf("%w: stream position has no session id", shared.ErrValidation)
	}
	if p.Boot == "" {
		return fmt.Errorf("%w: stream position has no boot id", shared.ErrValidation)
	}
	return nil
}

// DeliveryClass is how an incoming position relates to the last one accepted for the same stream.
type DeliveryClass string

const (
	// DeliveryOK — exactly the expected next sequence within the current incarnation.
	DeliveryOK DeliveryClass = "ok"
	// DeliveryForwardGap — ahead of the expected next in the current incarnation: one or more sequences are
	// unaccounted for (a potential loss the caller MUST surface as an explicit gap, never silently accept).
	DeliveryForwardGap DeliveryClass = "forward_gap"
	// DeliveryReplay — the incoming batch sequence is not ahead of the high-water within the current
	// incarnation. This covers BOTH a true duplicate AND a genuine late arrival that fills an earlier gap,
	// because ClassifyDelivery only knows the scalar high-water, not which sequences were actually received.
	// It therefore MUST NOT be treated as "discard the payload": the authority for "already have this
	// signal" is AckLedger.Observe / DeliveryKey (see below), and a below-high-water sequence is frequently
	// a real gap-fill that closes an outstanding gap. Equating !IsProgress() with drop would silently lose
	// exactly the signal the contract exists to preserve.
	DeliveryReplay DeliveryClass = "replay"
	// DeliveryNewIncarnation — a higher Epoch: a legitimate reboot/reinstall reset, NOT a replay even though
	// the Sequence dropped back toward 1. If the new incarnation's first sequence is > 1, Missing says how
	// many were lost across the restart.
	DeliveryNewIncarnation DeliveryClass = "new_incarnation"
	// DeliveryStaleIncarnation — a lower Epoch than the one already accepted: an old incarnation resurfacing
	// (a delayed/duplicated batch from before a restart). Treated as a replay-class event, never accepted as
	// forward progress.
	DeliveryStaleIncarnation DeliveryClass = "stale_incarnation"
)

// DeliveryOutcome is the classification plus, when relevant, how many sequences are unaccounted for.
type DeliveryOutcome struct {
	Class   DeliveryClass
	Missing uint64
}

// HasGap reports whether the outcome implies one or more sequences are missing.
func (o DeliveryOutcome) HasGap() bool { return o.Missing > 0 }

// IsProgress reports whether the incoming batch advances the high-water of its incarnation. OK,
// ForwardGap, and NewIncarnation are progress; Replay and StaleIncarnation are not.
//
// IsProgress is a classification of ORDERING, not a persistence decision. A caller must NOT read
// !IsProgress() as "drop this batch": a Replay may be a genuine gap-fill below the high-water. Decide
// idempotent persistence per event via DeliveryKey (dedup) and AckLedger.Observe (which returns true for a
// first-seen sequence — including a gap-fill — and false only for a true duplicate). Use IsProgress only to
// drive high-water/gap bookkeeping.
func (o DeliveryOutcome) IsProgress() bool {
	switch o.Class {
	case DeliveryOK, DeliveryForwardGap, DeliveryNewIncarnation:
		return true
	default:
		return false
	}
}

// ClassifyDelivery compares the last accepted position for a stream against an incoming one and says how
// they relate — the core of session-aware gap/replay/reset detection. Both positions are assumed to be the
// SAME priority stream (the caller partitions by priority). A zero-value `last` means nothing has been
// accepted yet, so the first incarnation is reported as NewIncarnation.
//
// Ordering is by Epoch first (incarnations), then Sequence within an incarnation — never by the opaque
// Session/Boot ids, which cannot be ordered. This is precisely what keeps a reboot's reset-to-1 from being
// mistaken for a replay: the reboot advanced Epoch, so it sorts AFTER the previous incarnation.
//
// The caller MUST have Validate()d `incoming` first (Epoch >= 1, Sequence >= 1); a zero-Epoch incoming
// against a zero-value last would otherwise fall through to the same-incarnation branch and read as a
// Replay. `last` is the last ACCEPTED position (its zero value means "nothing yet").
func ClassifyDelivery(last, incoming StreamPosition) DeliveryOutcome {
	switch {
	case incoming.Epoch > last.Epoch:
		// A new incarnation (or the very first). Its first sequence should be 1; anything higher means
		// batches were lost across the restart before this one reached us.
		var missing uint64
		if incoming.Sequence > 1 {
			missing = incoming.Sequence - 1
		}
		return DeliveryOutcome{Class: DeliveryNewIncarnation, Missing: missing}
	case incoming.Epoch < last.Epoch:
		return DeliveryOutcome{Class: DeliveryStaleIncarnation}
	default: // same incarnation
		if incoming.Sequence <= last.Sequence {
			return DeliveryOutcome{Class: DeliveryReplay}
		}
		missing := incoming.Sequence - last.Sequence - 1
		if missing > 0 {
			return DeliveryOutcome{Class: DeliveryForwardGap, Missing: missing}
		}
		return DeliveryOutcome{Class: DeliveryOK}
	}
}

// DeliveryKey is the idempotency key for one event within a batch: a resend of the same
// (agent, incarnation, stream, sequence, event index) is the SAME key, so the server's ingest can treat it
// as a no-op instead of storing a duplicate. It deliberately keys on Epoch too, so the same (stream,
// sequence, index) in a NEW incarnation is a distinct key (a legitimately different event after a reset),
// never collapsed into the pre-restart one.
//
// Fields are LENGTH-PREFIXED, not separator-joined: the agent id is a free-form string that could itself
// contain any separator byte, and a forged boundary in an idempotency key would let one event's ingest
// suppress a different event (a silent-loss vector). Length prefixing makes the decoding unambiguous
// regardless of field contents.
func DeliveryKey(agent shared.ID, pos StreamPosition, eventIndex int) string {
	var b strings.Builder
	write := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
	}
	write(agent.String())
	write(strconv.Itoa(int(pos.Priority))) // the raw discriminant, not String() (which maps every invalid value to "P?")
	write(strconv.FormatUint(pos.Epoch, 10))
	write(strconv.FormatUint(pos.Sequence, 10))
	write(strconv.Itoa(eventIndex))
	return b.String()
}

// SeqRange is an inclusive range of sequence numbers, used to report gaps compactly.
type SeqRange struct {
	From uint64 // inclusive
	To   uint64 // inclusive
}

// AckLedger tracks, for ONE stream incarnation, which sequences have been received, and derives the
// highest-contiguous ACK and the explicit gaps below it. The ACK a stream reports is the highest sequence
// S such that every sequence in 1..S has been received — so an ACK can never skip a hole, and any sequence
// received out of order above a hole is remembered but does NOT advance the ACK until the hole fills. The
// gaps are the still-missing sequences below the highest one received, i.e. the explicit, queryable
// "we know these are outstanding" set. A zero-value AckLedger is ready to use.
//
// NOT safe for concurrent use: it is a per-stream, per-caller accumulator — synchronize externally (or
// use one ledger per goroutine) rather than sharing an instance across goroutines.
type AckLedger struct {
	contiguous uint64          // highest S with all of 1..S received (0 = none yet)
	pending    map[uint64]bool // received sequences strictly beyond the contiguous run (out-of-order)
}

// NewAckLedger returns an empty ledger.
func NewAckLedger() *AckLedger { return &AckLedger{} }

// SeedContiguous rehydrates a ledger's contiguous high-water from durable state (A3 persists the ACK
// mark rather than replaying every sequence). It sets the base only on a fresh ledger; the caller then
// Observe()s the persisted pending set on top. Seeding a non-empty ledger is a no-op.
func (l *AckLedger) SeedContiguous(n uint64) {
	if l.contiguous == 0 && len(l.pending) == 0 {
		l.contiguous = n
	}
}

// Observe records that sequence seq has been received. It returns true if this is the first time seq is
// seen — INCLUDING a late arrival that fills an earlier gap below the high-water — and false if seq is a
// true duplicate (idempotent no-op) or invalid (0). This boolean is the authoritative "new vs already-have"
// signal the ingest path should gate persistence on (together with DeliveryKey), NOT ClassifyDelivery's
// progress flag. Receiving the sequence just above the contiguous run extends it, absorbing any previously
// out-of-order sequences that are now contiguous.
//
// The caller should bound an implausible forward jump BEFORE Observe (e.g. reject a batch whose
// ForwardGap.Missing is absurd): the pending set holds one entry per out-of-order sequence, so an
// untrusted agent that streams a huge spread of sparse sequences grows memory in proportion to what it
// sent. That back-pressure/quota is A2/A3's job; Observe itself does no per-call unbounded work.
func (l *AckLedger) Observe(seq uint64) bool {
	if seq == 0 || seq <= l.contiguous {
		return false // 0 is not a valid sequence; anything within the contiguous run is a duplicate
	}
	if l.pending[seq] {
		return false // already recorded out-of-order
	}
	if seq == l.contiguous+1 {
		l.contiguous++
		for l.pending[l.contiguous+1] {
			delete(l.pending, l.contiguous+1)
			l.contiguous++
		}
		return true
	}
	if l.pending == nil {
		l.pending = map[uint64]bool{}
	}
	l.pending[seq] = true
	return true
}

// HighestContiguous returns the ACK: the highest sequence with no hole beneath it (0 = nothing yet).
func (l *AckLedger) HighestContiguous() uint64 { return l.contiguous }

// Pending returns the received sequences strictly above the contiguous mark, ascending. It is the
// snapshot A3 persists (with HighestContiguous) so the ledger can be rehydrated across stateless ingests
// without replaying every sequence.
func (l *AckLedger) Pending() []uint64 {
	if len(l.pending) == 0 {
		return nil
	}
	out := make([]uint64, 0, len(l.pending))
	for s := range l.pending {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Gaps returns the still-missing sequence ranges below the highest sequence received, oldest first. An
// empty result means everything received so far is contiguous (nothing outstanding). These are the
// explicit gaps the contract requires be surfaced rather than silently tolerated.
func (l *AckLedger) Gaps() []SeqRange {
	if len(l.pending) == 0 {
		return nil
	}
	// Iterate the RECEIVED (pending) sequences, not the numeric range: cost is O(n log n) in the number of
	// out-of-order sequences held, never proportional to the largest sequence number an (untrusted) agent
	// sends. Every pending key is > contiguous+1 (contiguous absorbs contiguous+1 on arrival), so the hole
	// between one landmark and the next is a gap. The contiguous high-water is the first landmark.
	seqs := make([]uint64, 0, len(l.pending))
	for s := range l.pending {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var gaps []SeqRange
	prev := l.contiguous // everything <= contiguous is present
	for _, s := range seqs {
		if s > prev+1 {
			gaps = append(gaps, SeqRange{From: prev + 1, To: s - 1})
		}
		prev = s
	}
	return gaps
}

// SortSeqRanges orders ranges by their start, so callers comparing/persisting gap sets get a canonical
// order. (Gaps already returns ranges in order; this is for callers that merge ranges from many streams.)
func SortSeqRanges(rs []SeqRange) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].From < rs[j].From })
}
