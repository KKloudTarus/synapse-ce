package shared

import "strings"

// IsMachineActor reports whether actor belongs to one of Synapse's reserved non-human principal
// families. Human-only decisions use this shared predicate so a newly added machine namespace cannot
// accidentally be denied in one governance workflow but accepted in another.
func IsMachineActor(actor string) bool {
	actor = strings.ToLower(strings.TrimSpace(actor))
	if actor == "" {
		return true
	}
	for _, prefix := range []string{"agent:", "llm:", "mcp:", "system:", "machine:", "bot:", "service:"} {
		if strings.HasPrefix(actor, prefix) {
			return true
		}
	}
	return false
}
