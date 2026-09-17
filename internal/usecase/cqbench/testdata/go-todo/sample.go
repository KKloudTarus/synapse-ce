package sample

// TODO: replace the if-ladder with a lookup table before the 2.0 release.
func classify(n int) string {
	if n < 0 {
		return "neg"
	}
	if n == 0 {
		return "zero"
	}
	return "pos"
}
