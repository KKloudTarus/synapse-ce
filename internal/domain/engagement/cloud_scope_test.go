package engagement

import "testing"

func TestCloudAccountScopeIsExactAndTyped(t *testing.T) {
	s := Scope{InScope: []Target{{Kind: TargetCloudAccount, Value: "organization/o-1"}}}
	if !s.AllowsTarget(Target{Kind: TargetCloudAccount, Value: "organization/o-1"}) {
		t.Fatal("exact cloud root was denied")
	}
	if s.AllowsTarget(Target{Kind: TargetCloudAccount, Value: "organization/o-2"}) {
		t.Fatal("different cloud root was allowed")
	}
	if s.AllowsTarget(Target{Kind: TargetRepo, Value: "organization/o-1"}) {
		t.Fatal("different target kind was allowed")
	}
	if err := (Target{Kind: TargetCloudAccount, Value: "organization/o-1"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
