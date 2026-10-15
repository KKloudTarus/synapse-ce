package integration

import (
	"bytes"
	"testing"
)

func TestJiraCredentialAADBindsDestinationAndIdentity(t *testing.T) {
	item := Integration{TenantID: "tenant", ID: "connection", Provider: "jira-cloud", Endpoint: "https://test.atlassian.net"}
	baseline := CredentialAAD(item, "default")
	for _, field := range []string{"tenant", "id", "provider", "origin", "credential"} {
		t.Run(field, func(t *testing.T) {
			other := item
			identity := "default"
			switch field {
			case "tenant":
				other.TenantID = "foreign"
			case "id":
				other.ID = "other"
			case "provider":
				other.Provider = "jira-dc"
			case "origin":
				other.Endpoint = "https://other.atlassian.net"
			case "credential":
				identity = "other"
			}
			if bytes.Equal(baseline, CredentialAAD(other, identity)) {
				t.Fatal("credential AAD did not bind " + field)
			}
		})
	}
}

func TestExistingProviderCredentialAADRemainsCompatible(t *testing.T) {
	item := Integration{TenantID: "tenant", ID: "connection", Provider: "jenkins", Endpoint: "https://ci.example.com"}
	if string(CredentialAAD(item, "default")) != "synapse:integration-credential:tenant:connection:default" {
		t.Fatal("existing seal format changed")
	}
}
