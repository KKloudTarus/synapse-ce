package offensivepolicy

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/engagement"
	"github.com/KKloudTarus/synapse-ce/internal/domain/offensivepolicy"
)

func TestRoEFromEngagement(t *testing.T) {
	from := time.Unix(1_700_000_000, 0).UTC()
	to := from.Add(24 * time.Hour)
	e := engagement.Engagement{
		AuthorizedFrom:    &from,
		AuthorizedTo:      &to,
		CustomerContact:   "Ops",
		EmergencyContact:  "+1",
		RiskCeiling:       "high",
		ExclusionsChecked: true,
		Scope: engagement.Scope{
			InScope:    []engagement.Target{{Kind: engagement.TargetDomain, Value: "app.test"}},
			OutOfScope: []engagement.Target{{Kind: engagement.TargetIP, Value: "10.0.0.1"}},
		},
	}
	roe := RoEFromEngagement(e)
	if roe.CustomerContact != "Ops" || roe.EmergencyContact != "+1" || roe.RiskCeiling != offensivepolicy.RiskHigh || !roe.ExclusionsChecked {
		t.Fatalf("RoE fields wrong: %+v", roe)
	}
	if !roe.WindowStart.Equal(from) || !roe.WindowEnd.Equal(to) {
		t.Fatalf("window wrong: %v..%v", roe.WindowStart, roe.WindowEnd)
	}
	if len(roe.AuthorizedScope) != 1 || roe.AuthorizedScope[0] != "domain:app.test" {
		t.Fatalf("authorized scope wrong: %v", roe.AuthorizedScope)
	}
	if len(roe.ExcludedAssets) != 1 || roe.ExcludedAssets[0] != "ip:10.0.0.1" {
		t.Fatalf("excluded assets wrong: %v", roe.ExcludedAssets)
	}
	if missing := roe.missingFields(); len(missing) != 0 {
		t.Fatalf("complete RoE reported missing fields: %v", missing)
	}
	if missing := RoEFromEngagement(engagement.Engagement{}).missingFields(); len(missing) == 0 {
		t.Fatal("empty engagement produced a satisfiable RoE")
	}
}
