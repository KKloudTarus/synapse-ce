package bitbucket

import (
	"testing"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/integration"
	"github.com/KKloudTarus/synapse-ce/internal/domain/selfhosted"
)

func TestBitbucketProviderIsInboundOnly(t *testing.T) {
	r := integration.NewRegistry()
	if err := Register(r); err != nil {
		t.Fatal(err)
	}
	d, err := r.Descriptor(Provider)
	if err != nil || len(d.Capabilities) != 0 || len(d.SecretFields) != 0 {
		t.Fatalf("descriptor=%+v err=%v", d, err)
	}
	item := integration.Integration{ID: "bb", TenantID: "tenant", Provider: Provider, Name: "Bitbucket", Endpoint: "https://bitbucket.org", Config: []byte(`{}`), PollInterval: time.Minute, Version: 1}
	if _, err := New(item, nil, selfhosted.Rules{}); err != nil {
		t.Fatal(err)
	}
	if _, err := New(item, integration.CredentialBundle{"token": "not-accepted"}, selfhosted.Rules{}); err == nil {
		t.Fatal("inbound provider accepted an outbound credential")
	}
}
