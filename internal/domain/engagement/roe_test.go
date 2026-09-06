package engagement

import (
	"reflect"
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

func TestToolClassOf(t *testing.T) {
	cases := map[string]ToolClass{
		"sca.scan":        "sca",
		"recon.subfinder": "recon",
		"exploit":         "exploit",
		"":                "",
		"a.b.c":           "a",
	}
	for action, want := range cases {
		if got := ToolClassOf(action); got != want {
			t.Errorf("ToolClassOf(%q) = %q, want %q", action, got, want)
		}
	}
}

func TestRoEPermits(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	blackout := Blackout{From: now.Add(-time.Hour), To: now.Add(time.Hour)}
	cases := []struct {
		name   string
		roe    RoE
		class  ToolClass
		at     time.Time
		wantOK bool
		reason string
	}{
		{"empty allows all", RoE{}, "recon", now, true, ""},
		{"allowed class", RoE{AllowedToolClasses: []ToolClass{"sca", "recon"}}, "recon", now, true, ""},
		{"disallowed class", RoE{AllowedToolClasses: []ToolClass{"sca"}}, "recon", now, false, "tool_not_allowed"},
		{"inside blackout", RoE{Blackouts: []Blackout{blackout}}, "sca", now, false, "blackout_window"},
		{"outside blackout", RoE{Blackouts: []Blackout{blackout}}, "sca", now.Add(2 * time.Hour), true, ""},
		{"class ok but in blackout", RoE{AllowedToolClasses: []ToolClass{"sca"}, Blackouts: []Blackout{blackout}}, "sca", now, false, "blackout_window"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, reason := c.roe.Permits(c.class, c.at)
			if ok != c.wantOK || reason != c.reason {
				t.Errorf("Permits(%q,%v) = (%v,%q), want (%v,%q)", c.class, c.at, ok, reason, c.wantOK, c.reason)
			}
		})
	}
}

func TestOffensiveRoEComplete(t *testing.T) {
	full := OffensiveRoE{
		CustomerContact:    "soc@client.example",
		EmergencyContact:   "+1-555-0100",
		RiskCeiling:        offensivepolicy.RiskMedium,
		ExclusionsReviewed: true,
	}
	cases := []struct {
		name string
		roe  OffensiveRoE
		want bool
	}{
		{"complete", full, true},
		{"low ceiling ok", func() OffensiveRoE { r := full; r.RiskCeiling = offensivepolicy.RiskLow; return r }(), true},
		{"high ceiling ok", func() OffensiveRoE { r := full; r.RiskCeiling = offensivepolicy.RiskHigh; return r }(), true},
		{"missing customer contact", func() OffensiveRoE { r := full; r.CustomerContact = "  "; return r }(), false},
		{"missing emergency contact", func() OffensiveRoE { r := full; r.EmergencyContact = ""; return r }(), false},
		{"unset ceiling", func() OffensiveRoE { r := full; r.RiskCeiling = ""; return r }(), false},
		{"prohibited ceiling", func() OffensiveRoE { r := full; r.RiskCeiling = offensivepolicy.RiskProhibited; return r }(), false},
		{"exclusions not reviewed", func() OffensiveRoE { r := full; r.ExclusionsReviewed = false; return r }(), false},
		{"empty", OffensiveRoE{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.roe.Complete(); got != c.want {
				t.Errorf("Complete() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestSetOffensiveRoE(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	base := time.Unix(1_699_000_000, 0).UTC()

	t.Run("rejects non-executable ceiling", func(t *testing.T) {
		e := &Engagement{Audit: shared.Audit{UpdatedAt: base}}
		err := e.SetOffensiveRoE(OffensiveRoE{RiskCeiling: offensivepolicy.RiskProhibited}, now)
		if err == nil {
			t.Fatal("expected validation error for prohibited ceiling")
		}
		if !e.Audit.UpdatedAt.Equal(base) {
			t.Errorf("UpdatedAt changed on rejected set: %v", e.Audit.UpdatedAt)
		}
	})

	t.Run("accepts empty ceiling and stamps time", func(t *testing.T) {
		e := &Engagement{Audit: shared.Audit{UpdatedAt: base}}
		if err := e.SetOffensiveRoE(OffensiveRoE{CustomerContact: "a@b"}, now); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !e.Audit.UpdatedAt.Equal(now) {
			t.Errorf("UpdatedAt = %v, want %v", e.Audit.UpdatedAt, now)
		}
		if e.RoE.Offensive.CustomerContact != "a@b" {
			t.Errorf("offensive RoE not set: %+v", e.RoE.Offensive)
		}
	})

	t.Run("SetRoE preserves offensive rules", func(t *testing.T) {
		e := &Engagement{Audit: shared.Audit{UpdatedAt: base}}
		off := OffensiveRoE{
			CustomerContact:    "soc@client.example",
			EmergencyContact:   "+1-555-0100",
			RiskCeiling:        offensivepolicy.RiskHigh,
			ExclusionsReviewed: true,
		}
		if err := e.SetOffensiveRoE(off, now); err != nil {
			t.Fatalf("SetOffensiveRoE: %v", err)
		}
		if err := e.SetRoE(RoE{AllowedToolClasses: []ToolClass{"recon"}}, now); err != nil {
			t.Fatalf("SetRoE: %v", err)
		}
		if !reflect.DeepEqual(e.RoE.Offensive, off) {
			t.Errorf("SetRoE dropped offensive rules: got %+v, want %+v", e.RoE.Offensive, off)
		}
		if len(e.RoE.AllowedToolClasses) != 1 || e.RoE.AllowedToolClasses[0] != "recon" {
			t.Errorf("tool classes not applied: %+v", e.RoE.AllowedToolClasses)
		}
	})
}
