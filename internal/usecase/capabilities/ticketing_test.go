package capabilities

import "testing"

func TestTicketingCapabilityFollowsDeploymentSwitch(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		svc, err := NewService(Flags{Ticketing: enabled})
		if err != nil {
			t.Fatal(err)
		}
		got := find(t, svc.List(), "ticketing")
		if got.Planned || got.Enabled != enabled || got.Switch != "SYNAPSE_TICKETING_ENABLED" {
			t.Fatalf("ticketing = %+v", got)
		}
	}
}
