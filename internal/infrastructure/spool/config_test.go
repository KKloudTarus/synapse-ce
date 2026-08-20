package spool

import (
	"errors"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/fleetagent"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestDefaultConfigUsesNeverShedDurability(t *testing.T) {
	input := DefaultConfig()
	input.Dir = t.TempDir()
	input.Session = "s"
	input.Boot = "b"
	cfg, err := normalizeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	for priority := fleetagent.PriorityP0; priority <= fleetagent.PriorityP2; priority++ {
		if cfg.Sync[priority] != SyncAlways {
			t.Errorf("%s sync = %q, want always", priority, cfg.Sync[priority])
		}
	}
	if cfg.Sync[fleetagent.PriorityP3] != SyncBatch {
		t.Errorf("P3 sync = %q, want batch", cfg.Sync[fleetagent.PriorityP3])
	}
	if cfg.MaxGapBytes <= 0 || cfg.MaxRecordBytes+FrameOverheadBudget > cfg.SegmentBytes || cfg.SegmentBytes > cfg.MaxBytes-cfg.MaxGapBytes {
		t.Fatalf("invalid default size hierarchy: record=%d segment=%d gaps=%d quota=%d", cfg.MaxRecordBytes, cfg.SegmentBytes, cfg.MaxGapBytes, cfg.MaxBytes)
	}
}

func TestNormalizeConfigRejectsUnsafePolicies(t *testing.T) {
	base := testConfig(t)
	tests := []struct {
		name string
		edit func(*Config)
	}{
		{"missing directory", func(c *Config) { c.Dir = "" }},
		{"missing session", func(c *Config) { c.Session = "" }},
		{"missing boot", func(c *Config) { c.Boot = "" }},
		{"negative quota", func(c *Config) { c.MaxBytes = -1 }},
		{"gap budget over quota", func(c *Config) { c.MaxGapBytes = c.MaxBytes }},
		{"gap budget too small", func(c *Config) { c.MaxGapBytes = minimumGapReserve - 1 }},
		{"segment over quota", func(c *Config) { c.SegmentBytes = c.MaxBytes + 1 }},
		{"record plus overhead over segment", func(c *Config) { c.MaxRecordBytes = c.SegmentBytes - FrameOverheadBudget + 1 }},
		{"negative peek count", func(c *Config) { c.PeekRecords = -1 }},
		{"negative peek bytes", func(c *Config) { c.PeekBytes = -1 }},
		{"negative batch interval", func(c *Config) { c.BatchInterval = -time.Second }},
		{"P0 batching", func(c *Config) { c.Sync[fleetagent.PriorityP0] = SyncBatch }},
		{"P2 batching", func(c *Config) { c.Sync[fleetagent.PriorityP2] = SyncBatch }},
		{"unknown policy", func(c *Config) { c.Sync[fleetagent.PriorityP3] = "sometimes" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.Sync = clonePolicies(base.Sync)
			tt.edit(&cfg)
			_, err := normalizeConfig(cfg)
			if err == nil || !errors.Is(err, shared.ErrValidation) {
				t.Fatalf("normalize error = %v, want validation error", err)
			}
		})
	}
}

func TestNormalizeConfigFillsOptionalDefaults(t *testing.T) {
	cfg, err := normalizeConfig(Config{Dir: t.TempDir(), Session: "s", Boot: "b"})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	defaults := DefaultConfig()
	if cfg.MaxBytes != defaults.MaxBytes || cfg.PeekRecords != defaults.PeekRecords || cfg.Now == nil {
		t.Fatalf("defaults not applied: %#v", cfg)
	}
}

func clonePolicies(in map[fleetagent.DeliveryPriority]SyncPolicy) map[fleetagent.DeliveryPriority]SyncPolicy {
	out := make(map[fleetagent.DeliveryPriority]SyncPolicy, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
