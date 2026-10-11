package httpapi

import (
	"net/http"
	"strings"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	bitbucketSignatureHeader = "X-Hub-Signature"
	bitbucketEventHeader     = "X-Event-Key"
	bitbucketRequestHeader   = "X-Request-UUID"
)

func bitbucketEventMetadata(header http.Header, body []byte) (ports.InboundWebhookEvent, bool) {
	eventType, typeOK := singleInboundWebhookHeader(header, bitbucketEventHeader)
	requestID, idOK := singleInboundWebhookHeader(header, bitbucketRequestHeader)
	if len(requestID) == 38 && requestID[0] == '{' && requestID[37] == '}' {
		requestID = requestID[1:37]
	}
	idOK = idOK && len(requestID) == 36
	for i, c := range requestID {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				idOK = false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			idOK = false
		}
	}
	typeOK = typeOK && len(eventType) > 0 && len(eventType) <= 64
	for _, c := range eventType {
		if !((c >= 'a' && c <= 'z') || c == ':' || c == '_') {
			typeOK = false
		}
	}
	return ports.InboundWebhookEvent{Provider: "bitbucket", EventType: eventType, EventID: strings.ToLower(requestID), Body: body}, typeOK && idOK
}
