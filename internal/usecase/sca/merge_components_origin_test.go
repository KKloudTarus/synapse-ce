package sca

import (
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
)

func TestMergeComponentsTransfersVerifiedCentOSOriginWithoutLosingMetadata(t *testing.T) {
	prior := sbom.Component{
		Name: "bash", Version: "4.2.46-34.el7",
		PURL:     "pkg:rpm/centos/bash@4.2.46-34.el7?arch=x86_64&distro=centos-7",
		Supplier: "earlier-producer", Location: "earlier-location",
	}
	cataloged := sbom.WithVerifiedRPMOrigin(prior, "rhel-base")
	doc := &sbom.SBOM{Components: []sbom.Component{prior}}
	if added := mergeComponents(doc, []sbom.Component{cataloged}); added != 0 {
		t.Fatalf("duplicate package added %d times", added)
	}
	got := doc.Components[0]
	if got.Supplier != prior.Supplier || got.Location != prior.Location {
		t.Fatalf("producer metadata was replaced: %+v", got)
	}
	if identity := sbom.IdentityFromComponent(got); identity.Ecosystem != "Red Hat:7" {
		t.Fatalf("verified origin was lost: %+v", identity)
	}
}

func TestMergeComponentsDoesNotTrustClaimedOrConflictingCentOSOrigin(t *testing.T) {
	prior := sbom.Component{
		Name: "bash", Version: "4.2.46-34.el7",
		PURL: "pkg:rpm/centos/bash@4.2.46-34.el7?arch=x86_64&distro=centos-7&origin=rhel-base",
	}
	signed := sbom.WithVerifiedRPMOrigin(prior, "rhel-base")
	tests := []struct {
		name  string
		extra []sbom.Component
	}{
		{name: "PURL claim alone", extra: []sbom.Component{prior}},
		{name: "signed and unsigned installed collision", extra: []sbom.Component{signed, prior}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc := &sbom.SBOM{Components: []sbom.Component{prior}}
			mergeComponents(doc, test.extra)
			if len(doc.Components) != 1 {
				t.Fatalf("duplicate inventory components: %+v", doc.Components)
			}
			if identity := sbom.IdentityFromComponent(doc.Components[0]); identity.Status == sbom.IdentityResolved {
				t.Fatalf("untrusted or ambiguous origin became matchable: %+v", identity)
			}
		})
	}
}

func TestMergeComponentsDoesNotTransferCentOS7OriginToAnotherRelease(t *testing.T) {
	prior := sbom.Component{
		Name: "bash", Version: "4.2.46-34.el7",
		PURL: "pkg:rpm/centos/bash@4.2.46-34.el7?arch=x86_64&distro=centos-8",
	}
	signed := sbom.WithVerifiedRPMOrigin(sbom.Component{
		Name: prior.Name, Version: prior.Version,
		PURL: "pkg:rpm/centos/bash@4.2.46-34.el7?arch=x86_64&distro=centos-7",
	}, "rhel-base")
	doc := &sbom.SBOM{Components: []sbom.Component{prior}}
	if added := mergeComponents(doc, []sbom.Component{signed}); added != 1 || len(doc.Components) != 2 {
		t.Fatalf("verified package was suppressed by conflicting prior identity: added=%d components=%+v", added, doc.Components)
	}
	if identity := sbom.IdentityFromComponent(doc.Components[0]); identity.Status == sbom.IdentityResolved {
		t.Fatalf("CentOS 8 gained CentOS 7 provenance: %+v", identity)
	}
	if identity := sbom.IdentityFromComponent(doc.Components[1]); identity.Ecosystem != "Red Hat:7" {
		t.Fatalf("verified CentOS 7 package lost its advisory scope: %+v", identity)
	}
}

func TestMergeComponentsKeepsSignedPackageWhenEarlierPURLNamesAnotherPackage(t *testing.T) {
	prior := sbom.Component{
		Name: "bash", Version: "4.2.46-34.el7",
		PURL: "pkg:rpm/centos/curl@4.2.46-34.el7?arch=x86_64&distro=centos-7",
	}
	signed := sbom.WithVerifiedRPMOrigin(sbom.Component{
		Name: "bash", Version: "4.2.46-34.el7",
		PURL: "pkg:rpm/centos/bash@4.2.46-34.el7?arch=x86_64&distro=centos-7",
	}, "rhel-base")
	doc := &sbom.SBOM{Components: []sbom.Component{prior}}
	if added := mergeComponents(doc, []sbom.Component{signed}); added != 1 || len(doc.Components) != 2 {
		t.Fatalf("signed package was hidden behind a conflicting PURL: added=%d components=%+v", added, doc.Components)
	}
	if sbom.VerifiedRPMOrigin(doc.Components[0]) != "" {
		t.Fatal("an untrusted earlier PURL borrowed verified origin")
	}
	if identity := sbom.IdentityFromComponent(doc.Components[1]); identity.Package != "bash" || identity.Ecosystem != "Red Hat:7" {
		t.Fatalf("verified Bash identity was lost: %+v", identity)
	}
}
