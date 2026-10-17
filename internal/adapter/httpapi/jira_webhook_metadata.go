package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const jiraSignatureHeader = "X-Hub-Signature"

func jiraEventMetadata(provider string, header http.Header, body []byte) (ports.InboundWebhookEvent, bool) {
	digest := sha256.Sum256(body)
	id, ok := singleInboundWebhookHeader(header, "X-Atlassian-Webhook-Identifier")
	bodyIdentity := provider == "jira-dc" && len(header.Values("X-Atlassian-Webhook-Identifier")) == 0
	// Data Center does not document Cloud's delivery identifier contract. A
	// missing header uses signed-body identity; a malformed supplied header is
	// still refused. Both identities retain the same two-hour receipt window.
	if bodyIdentity {
		id, ok = "body:"+hex.EncodeToString(digest[:]), true
	}
	if !ok || len(id) == 0 || len(id) > 128 || strings.TrimSpace(id) != id {
		return ports.InboundWebhookEvent{}, false
	}
	for _, c := range id {
		if c < 0x21 || c > 0x7e {
			return ports.InboundWebhookEvent{}, false
		}
	}
	if !bodyIdentity {
		// The identifier is unsigned provider metadata. Persist only its digest:
		// a caller-controlled header must never become a credential-bearing row.
		identityDigest := sha256.Sum256([]byte(id))
		id = "delivery:" + hex.EncodeToString(identityDigest[:])
	}
	var payload struct {
		Event string `json:"webhookEvent"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Event == "" || len(payload.Event) > 64 {
		return ports.InboundWebhookEvent{}, false
	}
	return ports.InboundWebhookEvent{Provider: provider, EventID: id, EventType: payload.Event, PayloadSHA256: hex.EncodeToString(digest[:]), Body: body}, true
}
