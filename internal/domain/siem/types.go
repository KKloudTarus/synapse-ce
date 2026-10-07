package siem

import (
	"errors"
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Budgets are the production limits. Tests inject the clock and the random
// source; they do not sleep to prove a delay.
const (
	MaxNameLen        = 80
	MaxBatchRecords   = 100
	MaxBatchBytes     = 256 * 1024
	MaxRecordBytes    = 32 * 1024
	MaxResponseBytes  = 1 << 20
	MaxSealedBytes    = 48 * 1024
	MaxDiagnosticLen  = 240
	MaxAllowHosts     = 16
	MaxTickPartitions = 8
	MaxAttempts       = 8
	DefaultLease      = 30 * time.Second
	DefaultTickBudget = 5 * time.Second
	BaseRetry         = time.Second
	MaxRetry          = 5 * time.Minute
	ManifestRetention = 7 * 24 * time.Hour
	MappingVersion    = "synapse.siem.v2"
	EnvelopeVersion   = "synapse.siem.audit.v1"
	IncidentEnvelope  = "synapse.siem.incident.v1"
	OCSFSchemaVersion = "1.5.0"
	OCSFSchemaTag     = "1.5.0"
	ScrubberVersion   = "privacy.classify.v1"
)

// Provider is a sink implementation this package knows how to describe.
type Provider string

const (
	ProviderSplunk            Provider = "splunk_hec"
	ProviderElasticsearch     Provider = "elasticsearch"
	ProviderSyslogTLS         Provider = "syslog_tls"
	ProviderMicrosoftSentinel Provider = "microsoft_sentinel"
)

// Valid reports whether p is a supported provider.
func (p Provider) Valid() bool {
	return p == ProviderSplunk || p == ProviderElasticsearch || p == ProviderSyslogTLS || p == ProviderMicrosoftSentinel
}

// AckMode is the delivery guarantee the operator selected. It is never
// lowered silently when the remote side cannot honor it.
type AckMode string

const (
	AckHECAcceptance       AckMode = "hec_acceptance"
	AckIndexer             AckMode = "indexer_ack"
	AckBulkItem            AckMode = "bulk_item"
	AckTransportWrite      AckMode = "transport_write"
	AckIngestionAcceptance AckMode = "ingestion_acceptance"
)

// ValidFor reports whether the acknowledgement mode matches the provider and
// the operator's explicit indexer-ack capability flag.
func (m AckMode) ValidFor(p Provider, indexerAckSupported bool) bool {
	switch p {
	case ProviderSplunk:
		if m == AckHECAcceptance {
			return true
		}
		return m == AckIndexer && indexerAckSupported
	case ProviderElasticsearch:
		return m == AckBulkItem
	case ProviderSyslogTLS:
		return m == AckTransportWrite
	case ProviderMicrosoftSentinel:
		return m == AckIngestionAcceptance
	default:
		return false
	}
}

// Source is one cursor partition. Audit, live incident capture, and the
// historical backfill do not share a sequence.
type Source string

const (
	SourceAudit              Source = "audit"
	SourceIncidentLive       Source = "incident_live"
	SourceIncidentHistorical Source = "incident_historical"
)

// Valid reports whether s is a known partition.
func (s Source) Valid() bool {
	switch s {
	case SourceAudit, SourceIncidentLive, SourceIncidentHistorical:
		return true
	default:
		return false
	}
}

// Phase is the incident capture lane stored with each identity row.
type Phase string

const (
	PhaseLive       Phase = "live"
	PhaseHistorical Phase = "historical"
)

// DataClass is the notification vocabulary (signal, summary, detail) plus
// none, which exports nothing. The string values are checked against
// notification.DataClass in tests so this package cannot drift a synonym.
type DataClass string

const (
	ClassNone    DataClass = "none"
	ClassSignal  DataClass = "signal"
	ClassSummary DataClass = "summary"
	ClassDetail  DataClass = "detail"
)

// Valid reports whether c is a known class.
func (c DataClass) Valid() bool {
	switch c {
	case ClassNone, ClassSignal, ClassSummary, ClassDetail:
		return true
	default:
		return false
	}
}

// Rank orders classes. none is zero. An unknown class is not ranked.
func (c DataClass) Rank() (int, bool) {
	switch c {
	case ClassNone:
		return 0, true
	case ClassSignal:
		return 1, true
	case ClassSummary:
		return 2, true
	case ClassDetail:
		return 3, true
	default:
		return 0, false
	}
}

// Min returns the tighter of the two classes.
func Min(left, right DataClass) (DataClass, error) {
	lr, ok := left.Rank()
	if !ok {
		return "", fmt.Errorf("%w: unknown data class %q", shared.ErrValidation, left)
	}
	rr, ok := right.Rank()
	if !ok {
		return "", fmt.Errorf("%w: unknown data class %q", shared.ErrValidation, right)
	}
	if lr <= rr {
		return left, nil
	}
	return right, nil
}

// NotificationClass returns the matching notification vocabulary value.
// none has no notification equivalent and reports ok=false.
func (c DataClass) NotificationClass() (notification.DataClass, bool) {
	switch c {
	case ClassSignal:
		return notification.DataClassSignal, true
	case ClassSummary:
		return notification.DataClassSummary, true
	case ClassDetail:
		return notification.DataClassDetail, true
	default:
		return "", false
	}
}

// Replay chooses where a new destination generation starts. There is no
// implicit choice: cursor replays the committed backlog to the new host,
// head leaves that backlog on the previous host.
type Replay string

const (
	ReplayCursor Replay = "cursor"
	ReplayHead   Replay = "head"
)

// Valid reports whether r is an explicit start point.
func (r Replay) Valid() bool { return r == ReplayCursor || r == ReplayHead }

var (
	// ErrStaleLease is a compare-and-swap rejection of an expired or replaced owner.
	ErrStaleLease = errors.New("siem lease is stale")
	// ErrGap means the source moved without a verifiable successor. The cursor stays.
	ErrGap = errors.New("siem source gap")
	// ErrBlocked means the sink needs an operator before another send.
	ErrBlocked = errors.New("siem sink blocked")
)

// Problem is a safe, stored reason a partition did not advance.
type Problem struct {
	Kind    string
	Message string
}

// None reports whether the problem does not stop the partition.
func (p Problem) None() bool { return p.Kind == "" || p.Kind == "none" }
