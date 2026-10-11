package siem

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Sink is the operator configuration for one tenant destination. The secret
// is not a field: it is sealed elsewhere and addressed by SecretVersion.
type Sink struct {
	ID                  shared.ID `json:"id"`
	TenantID            shared.ID `json:"tenant_id"`
	Name                string    `json:"name"`
	Provider            Provider  `json:"provider"`
	Origin              string    `json:"origin"`
	Target              string    `json:"target"`
	DataClass           DataClass `json:"data_class"`
	AckMode             AckMode   `json:"ack_mode"`
	IndexerAckSupported bool      `json:"indexer_ack_supported"`
	AllowHosts          []string  `json:"allow_hosts,omitempty"`
	Paused              bool      `json:"paused"`
	Enabled             bool      `json:"enabled"`
	Generation          int64     `json:"generation"`
	SecretVersion       int64     `json:"secret_version"`
	Version             int64     `json:"version"`
	Channel             string    `json:"channel"`
	BlockedReason       string    `json:"blocked_reason,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// Validate checks a sink that is about to be stored.
func (s Sink) Validate() error {
	if s.ID.IsZero() || s.TenantID.IsZero() {
		return fmt.Errorf("%w: sink id and tenant are required", shared.ErrValidation)
	}
	if err := validateName(s.Name); err != nil {
		return err
	}
	if !s.Provider.Valid() {
		return fmt.Errorf("%w: unknown siem provider %q", shared.ErrValidation, s.Provider)
	}
	origin, err := ParseOriginFor(s.Provider, s.Origin)
	if err != nil {
		return err
	}
	if s.Origin != origin.String() {
		return fmt.Errorf("%w: sink origin must be stored in canonical form", shared.ErrValidation)
	}
	if s.Provider == ProviderMicrosoftSentinel && (!validSentinelOriginHost(origin.Host) || origin.Port != "" && origin.Port != "443") {
		return fmt.Errorf("%w: microsoft sentinel origin must be a public Azure Monitor ingestion endpoint on HTTPS port 443", shared.ErrValidation)
	}
	if err := HostAllowed(origin.Host, s.AllowHosts); err != nil {
		return err
	}
	if !s.DataClass.Valid() || s.DataClass == ClassNone {
		return fmt.Errorf("%w: sink data class must be signal, summary, or detail", shared.ErrValidation)
	}
	if !s.AckMode.ValidFor(s.Provider, s.IndexerAckSupported) {
		return fmt.Errorf("%w: acknowledgement mode %q is not supported for %s", shared.ErrValidation, s.AckMode, s.Provider)
	}
	if err := validateTarget(s.Provider, s.Target); err != nil {
		return err
	}
	if s.Generation < 1 || s.Version < 1 || s.SecretVersion < 1 {
		return fmt.Errorf("%w: sink generation, version, and secret version start at 1", shared.ErrValidation)
	}
	if s.Channel == "" || len(s.Channel) > 80 {
		return fmt.Errorf("%w: sink channel id is required", shared.ErrValidation)
	}
	if len(s.BlockedReason) > MaxDiagnosticLen {
		return fmt.Errorf("%w: sink blocked reason is too long", shared.ErrValidation)
	}
	return nil
}

func validateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > MaxNameLen {
		return fmt.Errorf("%w: sink name must be 1..%d characters", shared.ErrValidation, MaxNameLen)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: sink name contains a control character", shared.ErrValidation)
		}
	}
	return nil
}

func validateTarget(provider Provider, target string) error {
	raw := target
	target = strings.TrimSpace(target)
	switch provider {
	case ProviderSplunk:
		if target == "" {
			return fmt.Errorf("%w: splunk collector path is required", shared.ErrValidation)
		}
		if !strings.HasPrefix(target, "/") || strings.Contains(target, "..") || strings.ContainsAny(target, "?# ") {
			return fmt.Errorf("%w: splunk collector path must be an absolute path without a query", shared.ErrValidation)
		}
	case ProviderElasticsearch:
		if !validIndex(target) {
			return fmt.Errorf("%w: elasticsearch target must be one normal index name", shared.ErrValidation)
		}
	case ProviderSyslogTLS:
		if target == "" || len(target) > 48 {
			return fmt.Errorf("%w: syslog app name must be 1..48 printable ASCII characters", shared.ErrValidation)
		}
		for _, r := range target {
			if r < 33 || r > 126 {
				return fmt.Errorf("%w: syslog app name must be 1..48 printable ASCII characters", shared.ErrValidation)
			}
		}
	case ProviderMicrosoftSentinel:
		if raw != target || !validSentinelTarget(target) {
			return fmt.Errorf("%w: microsoft sentinel target must be dcr-<32 lowercase hex>/Custom-<stream>", shared.ErrValidation)
		}
	default:
		return fmt.Errorf("%w: unknown siem provider", shared.ErrValidation)
	}
	return nil
}

func validSentinelOriginHost(host string) bool {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	const suffix = ".ingest.monitor.azure.com"
	return len(name) > len(suffix) && strings.HasSuffix(name, suffix)
}

func validSentinelTarget(target string) bool {
	dcr, stream, ok := strings.Cut(target, "/")
	if !ok || strings.Contains(stream, "/") || len(dcr) != 36 || !strings.HasPrefix(dcr, "dcr-") {
		return false
	}
	for _, r := range dcr[4:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	if !strings.HasPrefix(stream, "Custom-") || len(stream) <= len("Custom-") || len(stream) > 128 {
		return false
	}
	for _, r := range stream {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// validIndex rejects data-stream-style and unsafe index names. The bulk
// driver writes with the index action only, on this one name.
func validIndex(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	if name[0] == '_' || name[0] == '-' || name[0] == '+' || name[0] == '.' {
		return false
	}
	for _, r := range name {
		if r > 0x7f || unicode.IsSpace(r) || unicode.IsUpper(r) {
			return false
		}
		switch r {
		case '\\', '/', '*', '?', '"', '<', '>', '|', ' ', ',', '#', ':':
			return false
		}
	}
	return true
}

// NormalizeOrigin returns the canonical origin or a validation error.
func NormalizeOrigin(raw string) (string, error) {
	origin, err := ParseOrigin(raw)
	if err != nil {
		return "", err
	}
	return origin.String(), nil
}

// NormalizeOriginFor returns the provider-specific canonical origin.
func NormalizeOriginFor(provider Provider, raw string) (string, error) {
	origin, err := ParseOriginFor(provider, raw)
	if err != nil {
		return "", err
	}
	return origin.String(), nil
}
