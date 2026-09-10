package sca

import (
	"os"
	"testing"

	"github.com/KKloudTarus/synapse-ce/internal/domain/sbom"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// TestStampOwnedLayerIDs verifies the owned-cataloger layer attribution: a component whose on-disk Location
// maps to a layer gets that layer's diff_id; a component that already has a LayerID (syft), one whose Location
// is not under the rootfs, and one whose file is unmapped are all left unchanged.
func TestStampOwnedLayerIDs(t *testing.T) {
	rootfs := "/scan/rootfs"
	sep := string(os.PathSeparator)
	ws := &ports.Workspace{
		RootFS: rootfs,
		RootFSLayers: map[string]string{
			"var/lib/dpkg/status":             "sha256:base",
			"app/node_modules/x/package.json": "sha256:app",
		},
	}
	doc := &sbom.SBOM{Components: []sbom.Component{
		{Name: "libc", Version: "1", PURL: "pkg:deb/debian/libc@1", Location: rootfs + sep + "var/lib/dpkg/status"},
		{Name: "x", Version: "2", PURL: "pkg:npm/x@2", Location: rootfs + sep + "app/node_modules/x/package.json"},
		{Name: "syftpkg", Version: "3", PURL: "pkg:deb/debian/syftpkg@3", LayerID: "sha256:already"},
		{Name: "unmapped", Version: "4", PURL: "pkg:pypi/unmapped@4", Location: rootfs + sep + "opt/thing/METADATA"},
		{Name: "outside", Version: "5", PURL: "pkg:pypi/outside@5", Location: "/other/place/METADATA"},
	}}

	stampOwnedLayerIDs(ws, doc)

	want := map[string]string{
		"libc":     "sha256:base",    // owned, mapped
		"x":        "sha256:app",     // owned, mapped
		"syftpkg":  "sha256:already", // already attributed (syft) - not overridden
		"unmapped": "",               // owned but its file is not in the layer map
		"outside":  "",               // Location not under the rootfs
	}
	for _, c := range doc.Components {
		if c.LayerID != want[c.Name] {
			t.Errorf("%s LayerID = %q, want %q", c.Name, c.LayerID, want[c.Name])
		}
	}

	// No-op guards: nil workspace, nil doc, empty rootfs, and no layer map must not panic and must change nothing.
	stampOwnedLayerIDs(nil, doc)
	stampOwnedLayerIDs(ws, nil)
	stampOwnedLayerIDs(&ports.Workspace{RootFS: "", RootFSLayers: ws.RootFSLayers}, doc)
	stampOwnedLayerIDs(&ports.Workspace{RootFS: rootfs}, doc)
	if doc.Components[3].LayerID != "" {
		t.Errorf("unmapped component must stay unattributed across no-op calls, got %q", doc.Components[3].LayerID)
	}
}
