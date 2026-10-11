package messageformat

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/domain/msgtemplate"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// ErrInvalidLink reports a link that is not an absolute https URL without credentials. Links are
// built server-side, so this is a programming error; the formatter refuses the message rather than
// send a link it cannot vouch for.
var ErrInvalidLink = errors.New("messageformat: invalid link")

const maxLinkLabelRunes = 80

// link is a checked RenderedLink: its URL is canonical and its label is sanitized and bounded.
type link struct {
	label string
	url   string
}

func checkLinks(links []ports.RenderedLink) ([]link, error) {
	out := make([]link, 0, len(links))
	for i, l := range links {
		u, err := url.Parse(l.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.ContainsAny(l.URL, " \t\r\n<>\"|") {
			return nil, fmt.Errorf("%w: link %d", ErrInvalidLink, i)
		}
		label := truncateRunes(strings.TrimSpace(msgtemplate.Sanitize(l.Label)), maxLinkLabelRunes)
		if label == "" {
			label = u.Host
		}
		out = append(out, link{label: label, url: u.String()})
	}
	return out, nil
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
