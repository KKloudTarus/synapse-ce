// Package dastconfig owns the canonical, secret-free authenticated scan policy.
package dastconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/dastsession"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastcrawl"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/dastrunner"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

type ScanCeilings struct {
	MaxReauth   int
	RatePerSec  int
	Concurrency int
	Limits      dastcrawl.Limits
}

func DefaultScanCeilings() ScanCeilings {
	return ScanCeilings{MaxReauth: dastsession.DefaultMaxReauth, RatePerSec: ports.DefaultDASTRatePerSec, Concurrency: ports.DefaultDASTConcurrency, Limits: dastcrawl.Limits{Depth: dastcrawl.DefaultDepth, Pages: dastcrawl.DefaultPages, Requests: dastcrawl.DefaultRequests, WallClock: dastcrawl.DefaultWallClock}}
}

type ScanConfig struct {
	Target           string             `json:"target"`
	Session          dastsession.Config `json:"session"`
	Crawler          dastcrawl.Input    `json:"crawler"`
	Limits           dastcrawl.Limits   `json:"limits"`
	RatePerSec       int                `json:"rate_per_sec"`
	Concurrency      int                `json:"concurrency"`
	SelectedCheckIDs []string           `json:"selected_check_ids,omitempty"`
}

// Canonical normalizes defaults and returns both the normalized value and the exact
// bytes and SHA-256 that must be bound to approval and the durable job.
func Canonical(c ScanConfig, ceilings ScanCeilings) (ScanConfig, []byte, string, error) {
	invalid := func(message string) (ScanConfig, []byte, string, error) {
		return ScanConfig{}, nil, "", fmt.Errorf("%w: %s", shared.ErrValidation, message)
	}
	if strings.TrimSpace(c.Target) == "" || c.Target != c.Crawler.Target {
		return invalid("DAST target must match crawler target")
	}
	if err := dastrunner.ValidateURL(c.Target); err != nil {
		return ScanConfig{}, nil, "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return ScanConfig{}, nil, "", err
	}
	if strings.Contains(strings.ToLower(string(raw)), "{{secret:") {
		return invalid("DAST configuration cannot contain secret placeholders")
	}
	if c.Session.MaxReauth == 0 {
		c.Session.MaxReauth = ceilings.MaxReauth
	}
	if c.RatePerSec == 0 {
		c.RatePerSec = ceilings.RatePerSec
	}
	if c.Concurrency == 0 {
		c.Concurrency = ceilings.Concurrency
	}
	if c.Limits.Depth == 0 {
		c.Limits.Depth = ceilings.Limits.Depth
	}
	if c.Limits.Pages == 0 {
		c.Limits.Pages = ceilings.Limits.Pages
	}
	if c.Limits.Requests == 0 {
		c.Limits.Requests = ceilings.Limits.Requests
	}
	if c.Limits.WallClock == 0 {
		c.Limits.WallClock = ceilings.Limits.WallClock
	}
	if c.Session.MaxReauth < 0 || c.Session.MaxReauth > ceilings.MaxReauth || c.RatePerSec < 1 || c.RatePerSec > ceilings.RatePerSec || c.Concurrency < 1 || c.Concurrency > ceilings.Concurrency || c.Limits.Depth < 1 || c.Limits.Depth > ceilings.Limits.Depth || c.Limits.Pages < 1 || c.Limits.Pages > ceilings.Limits.Pages || c.Limits.Requests < 1 || c.Limits.Requests > ceilings.Limits.Requests || c.Limits.WallClock < 1 || c.Limits.WallClock > ceilings.Limits.WallClock {
		return invalid("DAST scan configuration exceeds configured ceilings")
	}
	if err := c.Session.Validate(); err != nil {
		return ScanConfig{}, nil, "", err
	}
	for _, binding := range c.Session.Credentials {
		if strings.Contains(binding.Reference, "{{") || strings.ContainsAny(binding.Reference, "\r\n") {
			return invalid("invalid vault credential reference")
		}
	}
	c.SelectedCheckIDs = append([]string(nil), c.SelectedCheckIDs...)
	sort.Strings(c.SelectedCheckIDs)
	for i := 1; i < len(c.SelectedCheckIDs); i++ {
		if c.SelectedCheckIDs[i] == c.SelectedCheckIDs[i-1] {
			return invalid("duplicate DAST check " + c.SelectedCheckIDs[i])
		}
	}
	raw, err = json.Marshal(c)
	if err != nil {
		return ScanConfig{}, nil, "", err
	}
	digest := sha256.Sum256(raw)
	return c, raw, hex.EncodeToString(digest[:]), nil
}

// Decode strictly accepts exactly one JSON value and applies the same policy.
func Decode(raw []byte, ceilings ScanCeilings) (ScanConfig, []byte, string, error) {
	if err := rejectDuplicateKeys(raw); err != nil {
		return ScanConfig{}, nil, "", fmt.Errorf("%w: invalid DAST scan configuration: %v", shared.ErrValidation, err)
	}
	var c ScanConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return ScanConfig{}, nil, "", fmt.Errorf("%w: invalid DAST scan configuration: %v", shared.ErrValidation, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ScanConfig{}, nil, "", fmt.Errorf("%w: trailing DAST scan configuration", shared.ErrValidation)
	}
	return Canonical(c, ceilings)
}

// Reject ambiguous object keys before different components interpret the input.
func rejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var value func() error
	value = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("invalid object key")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				if err := value(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := value(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		default:
			return fmt.Errorf("unexpected delimiter")
		}
	}
	return value()
}
