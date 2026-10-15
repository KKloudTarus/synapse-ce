package integration

import "encoding/json"

// CredentialAAD preserves the shipped seal format for existing providers. Jira
// credentials additionally bind the provider and canonical endpoint. JSON arrays
// delimit identities without relying on user-controlled separator characters.
func CredentialAAD(item Integration, credentialID string) []byte {
	if item.Provider != "jira-cloud" && item.Provider != "jira-dc" {
		return []byte("synapse:integration-credential:" + item.TenantID.String() + ":" + item.ID.String() + ":" + credentialID)
	}
	encoded, _ := json.Marshal([]string{"synapse:integration-credential:v2", item.TenantID.String(), item.ID.String(), credentialID, string(item.Provider), item.Endpoint})
	return encoded
}
