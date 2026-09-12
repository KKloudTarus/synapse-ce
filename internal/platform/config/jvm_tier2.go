package config

const jvmTier2PointsToEnv = "SYNAPSE_JVM_REACH_TIER2_POINTS_TO_ENABLED"

// JVMTier2PointsToEnabled reports whether the optional Andersen-style receiver points-to refinement is
// enabled for the owned JVM Tier-2 call graph. It is deliberately OFF by default: CHA is the recall-first
// production posture, while points-to can only narrow virtual targets when its receiver facts are complete.
func (Config) JVMTier2PointsToEnabled() bool {
	return getbool(jvmTier2PointsToEnv, false)
}
