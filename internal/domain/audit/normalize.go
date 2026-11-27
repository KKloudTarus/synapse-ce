package audit

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NormalizeText returns s with every run of bytes that is not valid UTF-8 replaced by U+FFFD. A writer
// hashes and stores the normalized value, so the stored row recomputes to its hash. Without it the hash
// covers the raw bytes while JSON encoding (metadata) or the database (text columns) keeps another
// value, and the row reads as tampered forever.
func NormalizeText(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "�")
}

// NormalizeMetadata applies NormalizeText to every key and value. It returns metadata itself when nothing
// changes, and a copy otherwise. Two keys that normalize to the same key are refused with
// shared.ErrValidation: keeping either would drop the other from the record without a trace.
func NormalizeMetadata(metadata map[string]string) (map[string]string, error) {
	clean := true
	for k, v := range metadata {
		if !utf8.ValidString(k) || !utf8.ValidString(v) {
			clean = false
			break
		}
	}
	if clean {
		return metadata, nil
	}
	out := make(map[string]string, len(metadata))
	for k, v := range metadata {
		key := NormalizeText(k)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%w: audit metadata keys %q collide once invalid UTF-8 is replaced", shared.ErrValidation, key)
		}
		out[key] = NormalizeText(v)
	}
	return out, nil
}
