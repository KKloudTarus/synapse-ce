package privacy

import "regexp"

var urlCredentials = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/@\s]+@`)

// ScrubURLCredentials removes both password and token-only URL userinfo from free text.
func ScrubURLCredentials(value string) string {
	return urlCredentials.ReplaceAllString(value, "$1***@")
}
