package config

import (
	"reflect"
	"testing"
)

func TestTargetFloorConfiguration(t *testing.T) {
	t.Run("defaults refuse", func(t *testing.T) {
		t.Setenv("SYNAPSE_LOCAL_SCAN_ROOTS", "")
		t.Setenv("SYNAPSE_ALLOW_PRIVATE_ACQUISITION_ORIGINS", "")
		cfg := Load()
		if len(cfg.LocalScanRoots) != 0 || cfg.AllowPrivateAcquisitionOrigins {
			t.Fatalf("defaults = %v / %v, want no roots and private origins refused", cfg.LocalScanRoots, cfg.AllowPrivateAcquisitionOrigins)
		}
	})
	t.Run("operator sets both", func(t *testing.T) {
		t.Setenv("SYNAPSE_LOCAL_SCAN_ROOTS", " /srv/code , ,/opt/checkouts")
		t.Setenv("SYNAPSE_ALLOW_PRIVATE_ACQUISITION_ORIGINS", "true")
		cfg := Load()
		if want := []string{"/srv/code", "/opt/checkouts"}; !reflect.DeepEqual(cfg.LocalScanRoots, want) {
			t.Fatalf("roots = %q, want %q", cfg.LocalScanRoots, want)
		}
		if !cfg.AllowPrivateAcquisitionOrigins {
			t.Fatal("SYNAPSE_ALLOW_PRIVATE_ACQUISITION_ORIGINS=true was not honoured")
		}
	})
}
