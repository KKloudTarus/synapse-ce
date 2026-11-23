package cloudposture

import "testing"

func TestNormalizeRootAcceptsCanonicalScopeIdentity(t *testing.T) {
	for _, provider := range []Provider{ProviderAWS, ProviderAzure, ProviderGCP} {
		if _, _, err := NormalizeRoot(provider, string(provider)+":"); err == nil {
			t.Fatalf("empty qualified %s root accepted", provider)
		}
	}
	for _, tt := range []struct {
		provider Provider
		root     string
		key      string
	}{
		{ProviderAWS, "o-example", "aws:organizations/o-example"},
		{ProviderAzure, "subscriptions/sub-example", "azure:subscriptions/sub-example"},
		{ProviderAzure, "managementGroups/group-example", "azure:managementGroups/group-example"},
		{ProviderGCP, "projects/project-example", "gcp:projects/project-example"},
		{ProviderGCP, "folders/folder-example", "gcp:folders/folder-example"},
	} {
		t.Run(tt.key, func(t *testing.T) {
			root, key, err := NormalizeRoot(tt.provider, tt.key)
			if err != nil || root != tt.root || key != tt.key {
				t.Fatalf("canonical identity changed: root=%q key=%q err=%v", root, key, err)
			}
			_, nativeKey, err := NormalizeRoot(tt.provider, tt.root)
			if err != nil || nativeKey != key {
				t.Fatalf("native and canonical scope differ: %q != %q, %v", nativeKey, key, err)
			}
		})
	}
}
