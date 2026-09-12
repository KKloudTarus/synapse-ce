package acquire

import (
	"context"
	"errors"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

// newTestRegistry starts an in-memory OCI registry (go-containerregistry) on loopback and
// returns its host:port. It serves plain HTTP, which ggcr auto-selects for a loopback host.
func newTestRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// TestAcquireImageInProcessRegistry is the D7.7 acceptance test: an httptest OCI registry
// serving a small image produces the expected OCI layout with no external binary. PATH is
// emptied to prove the pull execs nothing — a crane-exec pull would fail with an empty PATH.
func TestAcquireImageInProcessRegistry(t *testing.T) {
	regHost := newTestRegistry(t)
	ref, err := name.ParseReference(regHost + "/synapse/test:latest")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	img, err := random.Image(2048, 2)
	if err != nil {
		t.Fatalf("build random image: %v", err)
	}
	pushTransport := &http.Transport{Proxy: nil}
	if err := remote.Write(ref, img, remote.WithContext(context.Background()), remote.WithTransport(pushTransport)); err != nil {
		t.Fatalf("push image to test registry: %v", err)
	}
	wantDigest, err := img.Digest()
	if err != nil {
		t.Fatalf("image digest: %v", err)
	}

	t.Setenv("PATH", "") // no external binary: a crane exec would fail; the in-process pull does not.

	acq := New()
	acq.allowInternalHosts = true // test-only: the httptest registry binds loopback, which the SSRF guard blocks.
	ws, err := acq.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetImage, Value: ref.Name()})
	if err != nil {
		t.Fatalf("in-process image pull failed: %v", err)
	}
	defer func() { _ = ws.Cleanup() }()

	for _, f := range []string{"index.json", "oci-layout"} {
		if _, serr := os.Stat(filepath.Join(ws.Dir, f)); serr != nil {
			t.Errorf("expected OCI layout file %s in workspace: %v", f, serr)
		}
	}

	// The layout must hold exactly the image we pushed, by digest — proves the pull fetched the
	// right content, not just that some files landed.
	idx, err := layout.ImageIndexFromPath(ws.Dir)
	if err != nil {
		t.Fatalf("read pulled layout: %v", err)
	}
	m, err := idx.IndexManifest()
	if err != nil {
		t.Fatalf("read layout index: %v", err)
	}
	if len(m.Manifests) != 1 {
		t.Fatalf("layout has %d manifests, want 1", len(m.Manifests))
	}
	if got := m.Manifests[0].Digest.String(); got != wantDigest.String() {
		t.Errorf("pulled digest %s, want %s", got, wantDigest)
	}
}

// TestAcquireImageManifestSizeCap proves the manifest-size front door rejects an image whose
// declared compressed bytes exceed the workspace cap, before any blob is written.
func TestAcquireImageManifestSizeCap(t *testing.T) {
	regHost := newTestRegistry(t)
	ref, err := name.ParseReference(regHost + "/synapse/big:latest")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	// Two 4 KiB (incompressible) layers: manifest JSON stays well under 2048 bytes so the
	// manifest fetch succeeds, but the declared image total exceeds the 2048-byte cap.
	img, err := random.Image(4096, 2)
	if err != nil {
		t.Fatalf("build random image: %v", err)
	}
	if err := remote.Write(ref, img, remote.WithContext(context.Background()), remote.WithTransport(&http.Transport{Proxy: nil})); err != nil {
		t.Fatalf("push image: %v", err)
	}

	acq := New().WithMaxWorkspaceBytes(2048)
	acq.allowInternalHosts = true
	_, err = acq.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetImage, Value: ref.Name()})
	if err == nil {
		t.Fatal("expected the oversized image to be rejected, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("want ErrValidation, got %v", err)
	}
}

// TestRegistryTransportRejectsUnlistedHost proves the egress pin refuses a dial to any host
// outside the allow-list, before DNS resolution.
func TestRegistryTransportRejectsUnlistedHost(t *testing.T) {
	rt := registryTransport([]string{"registry-1.docker.io"}, false, MaxWorkspaceBytes)
	client := &http.Client{Transport: rt}
	req, err := http.NewRequest(http.MethodGet, "https://evil.example.test/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected the unlisted host to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "not in the pull allow-list") {
		t.Errorf("want allow-list rejection, got %v", err)
	}
}

// TestRegistryTransportRejectsLoopback proves the egress pin refuses a dial to an allow-listed
// host that resolves to a loopback address (SSRF/metadata guard) when internal hosts are not
// permitted. localhost always resolves to loopback with no network access.
func TestRegistryTransportRejectsLoopback(t *testing.T) {
	rt := registryTransport([]string{"localhost"}, false, MaxWorkspaceBytes)
	client := &http.Client{Transport: rt}
	req, err := http.NewRequest(http.MethodGet, "http://localhost/v2/", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Do(req)
	if err == nil {
		t.Fatal("expected the loopback host to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "loopback/link-local") {
		t.Errorf("want SSRF/metadata rejection, got %v", err)
	}
}

// TestRegistryTransportBoundsResponseBody proves the shared pull budget fails closed once the
// TOTAL bytes read across responses exceed the cap, independent of the manifest-size check. Two
// responses each under the cap must together trip it, proving the budget is cumulative (a
// per-response cap would let an under-declared many-layer image write N×cap to disk).
func TestRegistryTransportBoundsResponseBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 10))
	}))
	defer srv.Close()
	host, _, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rt := registryTransport([]string{host}, true, 16) // 16-byte total budget, allowInternal for loopback
	client := &http.Client{Transport: rt}

	// First 10-byte response fits the 16-byte budget.
	resp1, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if _, rerr := io.ReadAll(resp1.Body); rerr != nil {
		t.Fatalf("first body should fit the budget, got %v", rerr)
	}
	_ = resp1.Body.Close()

	// Second 10-byte response pushes the cumulative total (20) past the 16-byte budget.
	resp2, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if _, rerr := io.ReadAll(resp2.Body); rerr == nil || !strings.Contains(rerr.Error(), "exceeds the 16-byte workspace cap") {
		t.Errorf("want cumulative-budget error, got %v", rerr)
	}
}

func TestHostWithoutPort(t *testing.T) {
	cases := map[string]string{
		"registry.internal:5000": "registry.internal",
		"127.0.0.1:5000":         "127.0.0.1",
		"docker.io":              "docker.io",
		"ghcr.io":                "ghcr.io",
		"localhost:5000":         "localhost",
	}
	for in, want := range cases {
		if got := hostWithoutPort(in); got != want {
			t.Errorf("hostWithoutPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistryHostsStripsPort(t *testing.T) {
	got := registryHosts("registry.internal:5000/team/app:1.2")
	if len(got) != 1 || got[0] != "registry.internal" {
		t.Errorf("registryHosts with an explicit port = %v, want [registry.internal]", got)
	}
}

// TestRegistryHostsCloudCDNs proves gcr.io and Google Artifact Registry refs allow-list the Google
// Cloud Storage blob host, so an anonymous public pull (e.g. gcr.io/distroless/*) is not broken by
// the blob redirect off the registry host.
func TestRegistryHostsCloudCDNs(t *testing.T) {
	cases := map[string][]string{
		"gcr.io/distroless/static:latest":     {"gcr.io", "storage.googleapis.com"},
		"us-docker.pkg.dev/proj/repo/app:1.0": {"us-docker.pkg.dev", "storage.googleapis.com"},
	}
	for ref, want := range cases {
		got := registryHosts(ref)
		gs, ws := append([]string(nil), got...), append([]string(nil), want...)
		sort.Strings(gs)
		sort.Strings(ws)
		if strings.Join(gs, ",") != strings.Join(ws, ",") {
			t.Errorf("registryHosts(%q) = %v, want %v", ref, got, want)
		}
	}
}

// TestIsInternalAcquisitionIP pins the SSRF/metadata guard: loopback, link-local, the standard and
// CGNAT cloud-metadata endpoints are refused; RFC1918 (self-hosted registry) and public IPs pass.
func TestIsInternalAcquisitionIP(t *testing.T) {
	reject := []string{"127.0.0.1", "::1", "169.254.169.254", "100.100.100.200", "0.0.0.0", "fe80::1", "fd00:ec2::254"}
	// 100.80.1.2 is a Tailscale tailnet address (CGNAT 100.64/10); a registry served over a tailnet
	// is a legitimate target, so only the exact Alibaba metadata IP in that range is blocked.
	allow := []string{"10.0.0.5", "192.168.1.10", "172.16.0.1", "8.8.8.8", "1.1.1.1", "fd12:3456::1", "100.80.1.2"}
	for _, s := range reject {
		if !isInternalAcquisitionIP(net.ParseIP(s)) {
			t.Errorf("isInternalAcquisitionIP(%s) = false, want true (must be refused)", s)
		}
	}
	for _, s := range allow {
		if isInternalAcquisitionIP(net.ParseIP(s)) {
			t.Errorf("isInternalAcquisitionIP(%s) = true, want false (must be reachable)", s)
		}
	}
}

// fakeManifestImage satisfies v1.Image but only serves a canned manifest; checkImageManifestSize
// calls no other method, so the embedded nil interface is never dereferenced.
type fakeManifestImage struct {
	v1.Image
	m *v1.Manifest
}

func (f fakeManifestImage) Manifest() (*v1.Manifest, error) { return f.m, nil }

// TestCheckImageManifestSize proves the manifest front door rejects a hostile manifest (negative,
// int64-overflowing, or too many layers) and an honestly-oversized one, and passes an honest image.
func TestCheckImageManifestSize(t *testing.T) {
	desc := func(sz int64) v1.Descriptor { return v1.Descriptor{Size: sz} }
	cases := []struct {
		name    string
		m       *v1.Manifest
		max     int64
		wantErr bool
	}{
		{"honest small", &v1.Manifest{Config: desc(10), Layers: []v1.Descriptor{desc(100), desc(200)}}, 2048, false},
		{"honest oversized", &v1.Manifest{Config: desc(10), Layers: []v1.Descriptor{desc(5000)}}, 2048, true},
		{"negative layer size", &v1.Manifest{Config: desc(0), Layers: []v1.Descriptor{desc(-1)}}, 2048, true},
		{"negative config size", &v1.Manifest{Config: desc(-5)}, 2048, true},
		{"int64 overflow", &v1.Manifest{Config: desc(0), Layers: []v1.Descriptor{desc(math.MaxInt64), desc(math.MaxInt64)}}, 2048, true},
		{"too many layers", &v1.Manifest{Config: desc(0), Layers: make([]v1.Descriptor, maxImageLayers+1)}, 1 << 40, true},
	}
	for _, tc := range cases {
		err := checkImageManifestSize(fakeManifestImage{m: tc.m}, tc.max)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
		if tc.wantErr && err != nil && !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want ErrValidation, got %v", tc.name, err)
		}
	}
}

// TestAcquireImageRejectsTooManyLayers pushes a real image with more layers than the cap and proves
// the pull is rejected before any blob is written (the goroutine/GET fan-out guard).
func TestAcquireImageRejectsTooManyLayers(t *testing.T) {
	regHost := newTestRegistry(t)
	ref, err := name.ParseReference(regHost + "/synapse/manylayers:latest")
	if err != nil {
		t.Fatalf("parse ref: %v", err)
	}
	img, err := random.Image(64, int64(maxImageLayers+4))
	if err != nil {
		t.Fatalf("build many-layer image: %v", err)
	}
	if err := remote.Write(ref, img, remote.WithContext(context.Background()), remote.WithTransport(&http.Transport{Proxy: nil})); err != nil {
		t.Fatalf("push image: %v", err)
	}
	acq := New()
	acq.allowInternalHosts = true
	_, err = acq.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetImage, Value: ref.Name()})
	if err == nil {
		t.Fatal("expected the many-layer image to be rejected, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "layer cap") {
		t.Errorf("want layer-cap ErrValidation, got %v", err)
	}
}

// TestAcquireImageDoesNotLeakRefCredentials proves that a reference carrying an embedded
// credential (which passes the character allow-list) never appears in the returned error, on any
// path — parse rejection or pull failure.
func TestAcquireImageDoesNotLeakRefCredentials(t *testing.T) {
	const secret = "s3cr3tP4ss"
	acq := New()
	_, err := acq.Acquire(context.Background(), ports.AcquireRequest{
		Kind:  ports.TargetImage,
		Value: "alice:" + secret + "@registry.example.test/acme/app:1",
	})
	if err == nil {
		t.Fatal("expected an error for a credential-bearing reference, got nil")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaked the embedded credential: %v", err)
	}
}

// refusingRunner fails the test if a sandboxed pull ever reaches the runner.
type refusingRunner struct{ t *testing.T }

func (r refusingRunner) Run(_ context.Context, spec ports.ToolSpec) (ports.ToolResult, error) {
	r.t.Fatalf("sandbox runner must not run for a fail-closed image pull; got %q", spec.Name)
	return ports.ToolResult{}, nil
}

// TestAcquireImageSandboxedFailsClosed pins invariant 2: a sandboxed acquirer without egress scoping
// (the production wiring, WithSandbox(sb,false)) must refuse a remote pull before any network or
// runner call.
func TestAcquireImageSandboxedFailsClosed(t *testing.T) {
	acq := New().WithSandbox(refusingRunner{t}, false)
	_, err := acq.Acquire(context.Background(), ports.AcquireRequest{Kind: ports.TargetImage, Value: "alpine:3.20"})
	if err == nil {
		t.Fatal("expected a fail-closed rejection, got nil")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Errorf("want ErrValidation, got %v", err)
	}
	if !strings.Contains(err.Error(), "requires authoritative signed execution grants") {
		t.Errorf("want the fail-closed message, got %v", err)
	}
}
