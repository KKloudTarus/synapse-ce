package siem

import "fmt"

// EngagementCeiling is the maximum class an engagement currently allows.
// Known is false when no shared engagement policy is available. That case
// fails closed to signal: it is not treated as detail.
type EngagementCeiling struct {
	Known bool
	Class DataClass
}

// EffectiveClass is the minimum of the sink class and the engagement ceiling.
// A record with no engagement is unscoped and cannot rise above signal.
// An explicit none ceiling suppresses the record. Suppression is not a gap.
func EffectiveClass(sink DataClass, engagementID string, ceiling EngagementCeiling) (DataClass, string, error) {
	if !sink.Valid() {
		return "", "", fmt.Errorf("unknown sink class %q", sink)
	}
	if engagementID == "" {
		class, err := Min(sink, ClassSignal)
		return class, "unscoped", err
	}
	if !ceiling.Known {
		class, err := Min(sink, ClassSignal)
		return class, "engagement_unknown", err
	}
	if !ceiling.Class.Valid() {
		return "", "", fmt.Errorf("unknown engagement class %q", ceiling.Class)
	}
	class, err := Min(sink, ceiling.Class)
	if err != nil {
		return "", "", err
	}
	if class == ClassNone {
		return ClassNone, "engagement_none", nil
	}
	return class, "engagement", nil
}
