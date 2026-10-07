package notification

import (
	"fmt"
	"sort"
	"strings"

	domain "github.com/KKloudTarus/synapse-ce/internal/domain/notification"
	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// errDestinationChange refuses a channel update that would re-point the channel for a caller
// without PermAdminister (#1358). The HTTP layer maps it to 403.
var errDestinationChange = fmt.Errorf("%w: changing a channel destination (URL, secret or recipients) requires the administer capability", shared.ErrForbidden)

// auditDestination is the masked destination recorded on every channel audit entry (#1358):
// scheme://host for URL channels, and mailto:// with the recipient domains for email. A path, a
// query, a token or a full address never reaches the audit log. An unparseable destination
// records nothing rather than guessing.
func auditDestination(c domain.Channel) string {
	if c.Type == domain.ChannelEmail {
		domains := map[string]bool{}
		for _, recipient := range c.Recipients {
			if _, host, ok := strings.Cut(recipient, "@"); ok && host != "" {
				domains[strings.ToLower(host)] = true
			}
		}
		if len(domains) == 0 {
			return ""
		}
		names := make([]string, 0, len(domains))
		for name := range domains {
			names = append(names, name)
		}
		sort.Strings(names)
		return "mailto://" + strings.Join(names, ",")
	}
	scheme, host, ok := domain.MaskedEndpoint(c.Destination)
	if !ok {
		return ""
	}
	return scheme + "://" + host
}

// channelAuditMetadata is the metadata every channel audit entry carries: the channel type and its
// masked destination. The actor is the entry's Actor. Channels have no data class yet (#1360), so
// none is recorded; the class joins this map when channels gain one.
func channelAuditMetadata(c domain.Channel, extra map[string]string) map[string]string {
	meta := map[string]string{"type": string(c.Type), "destination": auditDestination(c), "data_class": string(c.Class())}
	for k, v := range extra {
		meta[k] = v
	}
	return meta
}

// sameRecipients reports whether two normalized recipient lists name the same addresses.
func sameRecipients(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	left := append([]string(nil), a...)
	right := append([]string(nil), b...)
	sort.Strings(left)
	sort.Strings(right)
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
