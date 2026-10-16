package integrations

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
)

func TestJiraEndpointRulesFailClosed(t *testing.T) {
	cloud := integration.ProviderDescriptor{Provider: "jira-cloud"}
	for _, endpoint := range []string{"https://atlassian.net.attacker.test", "https://test.atlassian.net:444", "https://test.atlassian.net/path", "https://attacker.test", "http://test.atlassian.net"} {
		if err := checkEndpointRules(selfhosted.Rules{}, cloud, endpoint, false); err == nil {
			t.Errorf("accepted %s", endpoint)
		}
	}
	if err := checkEndpointRules(selfhosted.Rules{}, cloud, "https://test.atlassian.net", false); err != nil {
		t.Fatal(err)
	}
	if err := checkEndpointRules(selfhosted.Rules{}, cloud, "https://test.atlassian.net", true); err == nil {
		t.Fatal("accepted private Cloud")
	}
	dc := integration.ProviderDescriptor{Provider: "jira-dc", SelfHosted: true}
	if err := checkEndpointRules(selfhosted.Rules{}, dc, "https://jira.example.test", false); err == nil {
		t.Fatal("DC admitted with empty operator allowlist")
	}
}
