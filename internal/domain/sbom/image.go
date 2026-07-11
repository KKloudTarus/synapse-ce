package sbom

// Container-image layer attribution (Epic D). For an image scan, every package
// lives in a specific filesystem layer; ImageInfo carries the image's ordered
// layer stack (recovered from the OCI image config) so a vulnerability can be
// attributed to the layer that introduced it, and the base image (the OS/distro
// rootfs at the bottom of the stack) can be separated from the application
// layers added on top. Empty for non-image scans.

// ImageLayer is one filesystem layer of a container image. Only non-empty layers
// (those that change the filesystem and therefore have a diff_id) are recorded;
// metadata-only history entries (ENV/CMD/LABEL) are skipped because no package
// can live in them and they carry no diff_id to attribute against.
type ImageLayer struct {
	// Index is the layer's 0-based position in the stack, bottom (oldest) first.
	Index int `json:"index"`
	// DiffID is the layer's uncompressed content digest ("sha256:…"). It matches
	// Syft's per-component layerID, which is how a component is attributed to a layer.
	DiffID string `json:"diff_id"`
	// CreatedBy is the build command that produced the layer (from the image
	// history), e.g. "/bin/sh -c apt-get install -y openssl". Empty if the image
	// carried no history for this layer.
	CreatedBy string `json:"created_by,omitempty"`
	// Created is the layer's RFC3339 creation timestamp from the image history (optional).
	Created string `json:"created,omitempty"`
	// InBase reports whether this layer is classified as part of the base image
	// (the OS/distro rootfs + base packages) rather than application content added
	// on top. Set by MarkBaseLayers – a heuristic estimate, not authoritative.
	InBase bool `json:"in_base"`
}

// ImageInfo is the metadata Synapse recovers for a scanned container image: its
// identity (reference + manifest digest), platform, and ordered layer stack. It
// is read from the pulled OCI image config; absent for non-image scans.
type ImageInfo struct {
	Reference    string       `json:"reference"`              // the pulled image reference
	Digest       string       `json:"digest,omitempty"`       // manifest digest ("sha256:…")
	OS           string       `json:"os,omitempty"`           // e.g. "linux"
	Architecture string       `json:"architecture,omitempty"` // e.g. "amd64"
	Layers       []ImageLayer `json:"layers"`                 // ordered bottom→top (Index 0 = base rootfs)
	// BaseLayerCount is the number of bottom layers classified as the base image.
	// A heuristic ESTIMATE (see MarkBaseLayers): the count of layers below the first
	// layer that introduced an application (non-OS) package. Zero until classified.
	BaseLayerCount int `json:"base_layer_count"`
}

// LayerIndexByDiffID returns the stack index of the layer with the given diff_id,
// or -1 if no recorded layer matches (e.g. the component carried no layerID, or
// the image config and SBOM disagree). Pure lookup.
func (i *ImageInfo) LayerIndexByDiffID(diffID string) int {
	if i == nil || diffID == "" {
		return -1
	}
	for idx := range i.Layers {
		if i.Layers[idx].DiffID == diffID {
			return i.Layers[idx].Index
		}
	}
	return -1
}

// MarkBaseLayers separates the base image from the application layers using a
// conservative, deterministic heuristic: given the set of layer diff_ids that
// introduced at least one APPLICATION (non-OS) package, the base image is every
// layer BELOW the lowest such layer – i.e. the bottom run of layers that carry
// only OS/distro content. It sets InBase on those layers and BaseLayerCount.
//
// This is an ESTIMATE, not a definitive base-image identification: a multi-stage
// build that installs OS packages in an upper layer, or an app baked into the
// base image, will shift the boundary. It never fabricates a base-image name. If
// no layer introduced an application package (a pure OS image), every layer is
// treated as base. Callers should present the result as "estimated".
func (i *ImageInfo) MarkBaseLayers(appLayerDiffIDs map[string]bool) {
	if i == nil {
		return
	}
	// boundary = the lowest stack index that introduced an application package.
	// Layers strictly below it are the base image.
	boundary := len(i.Layers) // default: no app layer found ⇒ all layers are base
	for idx := range i.Layers {
		if appLayerDiffIDs[i.Layers[idx].DiffID] {
			boundary = i.Layers[idx].Index
			break
		}
	}
	base := 0
	for idx := range i.Layers {
		if i.Layers[idx].Index < boundary {
			i.Layers[idx].InBase = true
			base++
		} else {
			i.Layers[idx].InBase = false
		}
	}
	i.BaseLayerCount = base
}
