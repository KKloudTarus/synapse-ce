package sbom

import "testing"

func TestGitHubActionIdentityResolvesOnlyReleaseTags(t *testing.T) {
	for version, resolved := range map[string]bool{
		"4.1.2": true, "3.25": true, "1.0.0-rc.1": true,
		"v5": false, "4": false, "main": false, "fa0a91b85d4f404e444e00e005971372dc801d16": false,
	} {
		c := Component{Name: "actions/x", Version: version, PURL: "pkg:githubactions/actions/x@" + version}
		id := IdentityFromComponent(c)
		if (id.Status == IdentityResolved) != resolved {
			t.Errorf("%q: status %s (%s), resolved want %v", version, id.Status, id.Reason, resolved)
		}
		if id.Ecosystem != "GitHub Actions" || id.Package != "actions/x" {
			t.Errorf("%q: identity %+v", version, id)
		}
	}
}
