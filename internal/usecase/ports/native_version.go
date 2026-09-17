package ports

import "context"

// NativePackageFamily selects the target-native package comparison mechanism.
type NativePackageFamily string

const (
	NativePackageDeb NativePackageFamily = "deb"
	NativePackageRPM NativePackageFamily = "rpm"
)

// NativeVersionComparisonRequest keeps package versions as data. An adapter
// must execute these values through an argv-based target-native comparator and
// must not use host-side semantic comparison as a fallback.
type NativeVersionComparisonRequest struct {
	TargetDigest string
	Family       NativePackageFamily
	LeftEVR      string
	RightEVR     string
}

// NativeVersionComparisonResult represents LeftEVR relative to RightEVR.
// Relation is -1 (before), 0 (equal), or 1 (after).
type NativeVersionComparisonResult struct {
	Relation        int
	ExecutionDigest string
}

// NativeVersionComparator performs a comparison using a mechanism available
// inside the digest-pinned target environment. Implementations fail closed when
// that mechanism cannot be preflighted.
type NativeVersionComparator interface {
	CompareNativeVersion(context.Context, NativeVersionComparisonRequest) (NativeVersionComparisonResult, error)
}
