package jsresolve

// pnpmVersion keeps the existing helper contract while using the strict peer
// suffix parser shared by pnpm v9 package/snapshot verification.
func pnpmVersion(raw string) string {
	version, ok := pnpmResolvedBaseVersion(raw)
	if !ok {
		return ""
	}
	return version
}
