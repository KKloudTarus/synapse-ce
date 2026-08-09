package jsresolve

// deduplicateStrings removes adjacent duplicates from a sorted string slice.
// Yarn descriptor/version callers sort before invoking it so the operation is
// deterministic and allocation-free apart from the original slice.
func deduplicateStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value == out[len(out)-1] {
			continue
		}
		out = append(out, value)
	}
	return out
}
