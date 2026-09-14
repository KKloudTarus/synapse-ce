package config

import "testing"

func TestJVMTier2PointsToOptIn(t *testing.T) {
	t.Setenv(jvmTier2PointsToEnv, "")
	if (Config{}).JVMTier2PointsToEnabled() {
		t.Fatal("points-to must default off")
	}
	t.Setenv(jvmTier2PointsToEnv, "true")
	if !(Config{}).JVMTier2PointsToEnabled() {
		t.Fatal("explicit true must enable points-to")
	}
}
