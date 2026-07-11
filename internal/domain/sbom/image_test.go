package sbom

import "testing"

func TestMarkBaseLayers(t *testing.T) {
	// A 5-layer image: layers 0-2 are OS/distro (base), 3-4 introduce app packages.
	mk := func() *ImageInfo {
		return &ImageInfo{Layers: []ImageLayer{
			{Index: 0, DiffID: "sha256:a"},
			{Index: 1, DiffID: "sha256:b"},
			{Index: 2, DiffID: "sha256:c"},
			{Index: 3, DiffID: "sha256:d"},
			{Index: 4, DiffID: "sha256:e"},
		}}
	}

	t.Run("boundary at first app layer", func(t *testing.T) {
		img := mk()
		// app packages were introduced in layers d (3) and e (4)
		img.MarkBaseLayers(map[string]bool{"sha256:d": true, "sha256:e": true})
		if img.BaseLayerCount != 3 {
			t.Fatalf("BaseLayerCount = %d, want 3", img.BaseLayerCount)
		}
		for _, l := range img.Layers {
			want := l.Index < 3
			if l.InBase != want {
				t.Errorf("layer %d InBase=%v, want %v", l.Index, l.InBase, want)
			}
		}
	})

	t.Run("pure OS image – all base", func(t *testing.T) {
		img := mk()
		img.MarkBaseLayers(nil) // no app layers
		if img.BaseLayerCount != 5 {
			t.Fatalf("BaseLayerCount = %d, want 5 (all base)", img.BaseLayerCount)
		}
	})

	t.Run("app in the very first layer – no base", func(t *testing.T) {
		img := mk()
		img.MarkBaseLayers(map[string]bool{"sha256:a": true})
		if img.BaseLayerCount != 0 {
			t.Fatalf("BaseLayerCount = %d, want 0", img.BaseLayerCount)
		}
		if img.Layers[0].InBase {
			t.Error("layer 0 should not be base when it introduces an app package")
		}
	})

	t.Run("nil receiver is safe", func(t *testing.T) {
		var img *ImageInfo
		img.MarkBaseLayers(map[string]bool{"x": true}) // must not panic
	})
}

func TestLayerIndexByDiffID(t *testing.T) {
	img := &ImageInfo{Layers: []ImageLayer{
		{Index: 0, DiffID: "sha256:a"},
		{Index: 1, DiffID: "sha256:b"},
	}}
	if got := img.LayerIndexByDiffID("sha256:b"); got != 1 {
		t.Errorf("LayerIndexByDiffID(b) = %d, want 1", got)
	}
	if got := img.LayerIndexByDiffID("sha256:missing"); got != -1 {
		t.Errorf("missing diff_id = %d, want -1", got)
	}
	if got := img.LayerIndexByDiffID(""); got != -1 {
		t.Errorf("empty diff_id = %d, want -1", got)
	}
	var nilImg *ImageInfo
	if got := nilImg.LayerIndexByDiffID("sha256:a"); got != -1 {
		t.Errorf("nil image = %d, want -1", got)
	}
}
