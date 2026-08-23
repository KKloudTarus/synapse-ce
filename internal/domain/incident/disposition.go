package incident

// Disposition is the analyst's VERDICT on an incident — orthogonal to State (workflow position) and to
// risk. An incident can be, e.g., State=resolved with Disposition=false_positive, or State=investigating
// with Disposition=unknown. Disposition never mutates the risk score.
type Disposition string

const (
	DispositionUnknown       Disposition = "unknown"
	DispositionTruePositive  Disposition = "true_positive"
	DispositionBenign        Disposition = "benign_positive"
	DispositionFalsePositive Disposition = "false_positive"
	DispositionDuplicate     Disposition = "duplicate"
	DispositionTest          Disposition = "test"
)

// Valid reports whether d is a known disposition.
func (d Disposition) Valid() bool {
	switch d {
	case DispositionUnknown, DispositionTruePositive, DispositionBenign,
		DispositionFalsePositive, DispositionDuplicate, DispositionTest:
		return true
	default:
		return false
	}
}
