package user

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// NormalizeContactEmail validates a single mailbox used as a delivery destination.
// The local part is deliberately preserved: providers do not share dot, plus, or
// case-folding rules. A mailbox is never used as an account identity key.
func NormalizeContactEmail(value string) (string, error) {
	if value == "" || len(value) > 320 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return "", fmt.Errorf("%w: invalid contact email", shared.ErrValidation)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: invalid contact email", shared.ErrValidation)
		}
	}
	local, domain, ok := strings.Cut(value, "@")
	if !ok || local == "" || domain == "" || strings.Contains(domain, "@") || len(local) > 64 {
		return "", fmt.Errorf("%w: invalid contact email", shared.ErrValidation)
	}
	asciiDomain, err := idna.Lookup.ToASCII(domain)
	if err != nil || asciiDomain == "" || len(asciiDomain) > 253 || strings.HasPrefix(asciiDomain, ".") || strings.HasSuffix(asciiDomain, ".") {
		return "", fmt.Errorf("%w: invalid contact email", shared.ErrValidation)
	}
	result := local + "@" + strings.ToLower(asciiDomain)
	parsed, err := mail.ParseAddress(result)
	if err != nil || parsed.Address != result || parsed.Name != "" {
		return "", fmt.Errorf("%w: invalid contact email", shared.ErrValidation)
	}
	return result, nil
}
