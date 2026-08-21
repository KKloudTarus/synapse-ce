package detection

// Valid reports whether f is one of the closed matcher fields understood by this build.
func (f Field) Valid() bool {
	_, ok := fieldClass(f)
	return ok
}

// Numeric reports whether f is compared through the matcher's integer semantics.
func (f Field) Numeric() bool { return fieldIsNumeric(f) }
