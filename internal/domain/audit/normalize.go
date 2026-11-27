package audit

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NormalizeText returns s with every run of bytes that is not valid UTF-8, and every NUL, replaced by
// U+FFFD. A writer hashes and stores the normalized value, so the stored row recomputes to its hash.
// Without it the hash covers the raw bytes while JSON encoding keeps another value, and the row reads as
// tampered forever. A NUL is valid UTF-8 but Postgres text and jsonb refuse it, so it would fail the
// write and leave the action it records unaudited.
func NormalizeText(s string) string {
	if storable(s) {
		return s
	}
	return strings.ReplaceAll(strings.ToValidUTF8(s, replacement), "\x00", replacement)
}

// replacement is U+FFFD, the character encoding/json substitutes for an invalid byte.
const replacement = "\uFFFD"

// storable reports whether s is valid UTF-8 without a NUL, the form every audit store keeps unchanged.
func storable(s string) bool {
	return utf8.ValidString(s) && strings.IndexByte(s, 0) < 0
}

// NormalizeMetadata applies NormalizeText to every key and value. It returns metadata itself when nothing
// changes, and a copy otherwise. Two keys that normalize to the same key are refused with
// shared.ErrValidation: keeping either would drop the other from the record without a trace.
func NormalizeMetadata(metadata map[string]string) (map[string]string, error) {
	clean := true
	for k, v := range metadata {
		if !storable(k) || !storable(v) {
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
