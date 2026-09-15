package scabench

import "testing"

func TestRPMEVRCanonicalizesAbsentEpochToZero(t *testing.T) {
	value, err := (RPMEVR{Version: "1.2.3", Release: "4.fc40"}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if value != "0:1.2.3-4.fc40" {
		t.Fatalf("canonical RPM EVR = %q", value)
	}
	epoch := 2
	value, err = (RPMEVR{Epoch: &epoch, Version: "1.2.3", Release: "4.fc40"}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if value != "2:1.2.3-4.fc40" {
		t.Fatalf("canonical RPM EVR with epoch = %q", value)
	}
}
