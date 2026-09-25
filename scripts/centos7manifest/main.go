// centos7manifest generates a reproducible, small CentOS 7 package-header
// allowlist from the archived CentOS Vault. It intentionally writes downloaded
// RPMs only into a caller-supplied cache (normally .git/taurus), never the tree.
package main

import (
	"compress/gzip"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

const (
	defaultRepo        = "https://vault.centos.org/7.9.2009/os/x86_64/"
	centOS7Fingerprint = "6341AB2753D78A78A7C27BB124C6A8A7F4A80EB5"
	maxMetadataBytes   = 32 << 20
	maxRPMBytes        = 256 << 20
)

type repoMD struct {
	Data []struct {
		Type     string `xml:"type,attr"`
		Checksum struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"checksum"`
		Location struct {
			Href string `xml:"href,attr"`
		} `xml:"location"`
	} `xml:"data"`
}

type primaryMD struct {
	Packages []primaryPackage `xml:"package"`
}
type primaryPackage struct {
	Name    string `xml:"name"`
	Arch    string `xml:"arch"`
	Version struct {
		Epoch string `xml:"epoch,attr"`
		Ver   string `xml:"ver,attr"`
		Rel   string `xml:"rel,attr"`
	} `xml:"version"`
	Checksum struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	} `xml:"checksum"`
	Location struct {
		Href string `xml:"href,attr"`
	} `xml:"location"`
}

type manifest struct {
	Repository   string            `json:"repository"`
	RepomdSHA256 string            `json:"repomd_sha256"`
	Packages     []manifestPackage `json:"packages"`
}
type manifestPackage struct {
	Name                  string `json:"name"`
	EVR                   string `json:"evr"`
	Arch                  string `json:"arch"`
	RPMPath               string `json:"rpm_path"`
	RPMSHA256             string `json:"rpm_sha256"`
	ImmutableHeaderSHA256 string `json:"immutable_header_sha256"`
}

func main() {
	var repo, keyPath, cacheDir, output, selection string
	flag.StringVar(&repo, "repo", defaultRepo, "CentOS Vault repository URL")
	flag.StringVar(&keyPath, "key", "internal/infrastructure/tools/ospkg/testdata/centos-7-signing-key.asc", "pinned CentOS 7 key")
	flag.StringVar(&cacheDir, "cache", ".git/taurus/centos7-rpms", "RPM cache outside the worktree")
	flag.StringVar(&output, "output", "", "manifest JSON output (required)")
	flag.StringVar(&selection, "packages", "bash", "comma-separated exact package names")
	flag.Parse()
	if output == "" {
		die(errors.New("-output is required"))
	}
	if err := generate(repo, keyPath, cacheDir, output, strings.Split(selection, ",")); err != nil {
		die(err)
	}
}

func die(err error) { fmt.Fprintln(os.Stderr, "centos7manifest:", err); os.Exit(1) }

func generate(repo, keyPath, cacheDir, output string, wanted []string) error {
	base, err := canonicalBase(repo)
	if err != nil {
		return err
	}
	keys, err := pinnedKeyring(keyPath)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 45 * time.Second}
	repomd, err := getBounded(client, base+"repodata/repomd.xml", maxMetadataBytes)
	if err != nil {
		return fmt.Errorf("get repomd: %w", err)
	}
	sig, err := getBounded(client, base+"repodata/repomd.xml.asc", maxMetadataBytes)
	if err != nil {
		return fmt.Errorf("get repomd signature: %w", err)
	}
	if err := verifyRepomdSignature(keys, repomd, sig); err != nil {
		return fmt.Errorf("verify repomd signature with pinned CentOS key: %w", err)
	}
	var index repoMD
	if err := xml.Unmarshal(repomd, &index); err != nil {
		return fmt.Errorf("parse repomd: %w", err)
	}
	var primaryHref, primarySum string
	for _, d := range index.Data {
		if d.Type == "primary" {
			primaryHref, primarySum = d.Location.Href, d.Checksum.Value
			if d.Checksum.Type != "sha256" {
				return fmt.Errorf("primary checksum is %q, need sha256", d.Checksum.Type)
			}
			break
		}
	}
	if primaryHref == "" || !isSafeRepoPath(primaryHref) || len(primarySum) != 64 {
		return errors.New("repomd has no safe sha256 primary metadata")
	}
	primaryRaw, err := getBounded(client, base+primaryHref, maxMetadataBytes)
	if err != nil {
		return fmt.Errorf("get primary: %w", err)
	}
	if hashHex(primaryRaw) != strings.ToLower(primarySum) {
		return errors.New("primary metadata sha256 mismatch")
	}
	primary, err := parsePrimary(primaryRaw)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, n := range wanted {
		n = strings.TrimSpace(n)
		if n != "" {
			want[n] = true
		}
	}
	if len(want) == 0 {
		return errors.New("no package names selected")
	}
	selected := map[string]primaryPackage{}
	for _, p := range primary.Packages {
		if want[p.Name] && p.Arch == "x86_64" && p.Checksum.Type == "sha256" && len(p.Checksum.Value) == 64 && isSafeRepoPath(p.Location.Href) {
			selected[p.Name] = p
		}
	}
	if len(selected) != len(want) {
		return fmt.Errorf("selected %d of %d requested packages", len(selected), len(want))
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return fmt.Errorf("create cache: %w", err)
	}
	entries := make([]manifestPackage, 0, len(selected))
	for _, name := range sortedKeys(selected) {
		p := selected[name]
		path := filepath.Join(cacheDir, filepath.Base(p.Location.Href))
		rpm, err := cachedOrGet(client, path, base+p.Location.Href)
		if err != nil {
			return fmt.Errorf("get %s: %w", name, err)
		}
		if len(rpm) > maxRPMBytes {
			return fmt.Errorf("%s exceeds RPM byte limit", name)
		}
		if hashHex(rpm) != strings.ToLower(p.Checksum.Value) {
			return fmt.Errorf("%s RPM sha256 mismatch", name)
		}
		header, err := immutableMainHeader(rpm)
		if err != nil {
			return fmt.Errorf("extract %s immutable main header: %w", name, err)
		}
		entries = append(entries, manifestPackage{Name: p.Name, EVR: evr(p), Arch: p.Arch, RPMPath: p.Location.Href, RPMSHA256: strings.ToLower(p.Checksum.Value), ImmutableHeaderSHA256: hashHex(header)})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Name != entries[j].Name {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].EVR < entries[j].EVR
	})
	m := manifest{Repository: base, RepomdSHA256: hashHex(repomd), Packages: entries}
	data, err := jsonCompact(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func jsonCompact(v any) ([]byte, error) { return json.Marshal(v) }

func canonicalBase(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("repository must be an https URL without query or fragment")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String(), nil
}

func isSafeRepoPath(p string) bool {
	u, err := url.Parse(p)
	return err == nil && !u.IsAbs() && u.RawQuery == "" && u.Fragment == "" && !strings.HasPrefix(p, "/") && !strings.Contains(p, "..")
}

func pinnedKeyring(path string) (openpgp.EntityList, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	keys, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil || len(keys) != 1 {
		return nil, fmt.Errorf("read one armored key: %w", err)
	}
	if hex.EncodeToString(keys[0].PrimaryKey.Fingerprint[:]) != strings.ToLower(centOS7Fingerprint) {
		return nil, errors.New("key fingerprint does not match pinned CentOS 7 signer")
	}
	return keys, nil
}

// ProtonMail's packet reader intentionally omits legacy v3 signature packets.
// CentOS Vault's signed 7.9.2009 metadata uses that still-valid wire format.
// Parse its strictly bounded v3 RSA/SHA256 packet and verify it against the
// armored-key fingerprint already checked by pinnedKeyring.
func verifyRepomdSignature(keys openpgp.EntityList, signed, armored []byte) error {
	if len(keys) != 1 {
		return errors.New("exactly one pinned signer required")
	}
	body, err := decodeArmoredSignature(armored)
	if err != nil {
		return err
	}
	if len(body) < 21 || body[0] != 3 || body[1] != 5 || body[2] != 0 || body[15] != 1 || body[16] != 8 {
		return errors.New("unsupported repomd signature format")
	}
	issuer := uint64(0)
	for _, b := range body[7:15] {
		issuer = issuer<<8 | uint64(b)
	}
	if issuer != keys[0].PrimaryKey.KeyId {
		return errors.New("signature issuer does not match pinned key")
	}
	bits := int(body[19])<<8 | int(body[20])
	mpiLen := (bits + 7) / 8
	if bits < 512 || 21+mpiLen != len(body) {
		return errors.New("invalid RSA signature MPI")
	}
	pub, ok := keys[0].PrimaryKey.PublicKey.(*rsa.PublicKey)
	if !ok || bits > pub.N.BitLen() {
		return errors.New("pinned key is not a compatible RSA key")
	}
	h := sha256.New()
	_, _ = h.Write(signed)
	// RFC 4880 v3 signs the five-byte signature type and creation time.
	_, _ = h.Write(body[2:7])
	digest := h.Sum(nil)
	if body[17] != digest[0] || body[18] != digest[1] {
		return errors.New("repomd signature digest prefix mismatch")
	}
	s := new(big.Int).SetBytes(body[21:]).Bytes()
	padded := make([]byte, (pub.N.BitLen()+7)/8)
	copy(padded[len(padded)-len(s):], s)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, padded); err != nil {
		return fmt.Errorf("invalid detached signature: %w", err)
	}
	return nil
}

func decodeArmoredSignature(armored []byte) ([]byte, error) {
	text := string(armored)
	const begin = "-----BEGIN PGP SIGNATURE-----"
	const end = "-----END PGP SIGNATURE-----"
	start, finish := strings.Index(text, begin), strings.Index(text, end)
	if start != 0 || finish < 0 {
		return nil, errors.New("invalid ASCII-armored signature")
	}
	lines := strings.Split(text[len(begin):finish], "\n")
	var encoded strings.Builder
	data, sawHeader := false, false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			if sawHeader {
				data = true
			}
			continue
		}
		if !data && strings.Contains(line, ":") {
			sawHeader = true
			continue
		}
		if !data {
			return nil, errors.New("ASCII armor has no header separator")
		}
		if data {
			if strings.HasPrefix(line, "=") {
				break
			}
			encoded.WriteString(line)
		}
	}
	if encoded.Len() == 0 {
		return nil, errors.New("empty ASCII-armored signature")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		return nil, fmt.Errorf("decode ASCII armor: %w", err)
	}
	if len(decoded) < 3 || decoded[0] != 0x89 {
		return nil, errors.New("signature is not an old-format OpenPGP packet")
	}
	length := int(decoded[1])<<8 | int(decoded[2])
	if length != len(decoded)-3 {
		return nil, errors.New("signature packet length mismatch")
	}
	return decoded[3:], nil
}

func getBounded(client *http.Client, rawURL string, limit int64) ([]byte, error) {
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	if resp.ContentLength > limit {
		return nil, errors.New("response exceeds byte limit")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("response exceeds byte limit")
	}
	return b, nil
}

func cachedOrGet(client *http.Client, path, rawURL string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		return b, nil
	}
	b, err := getBounded(client, rawURL, maxRPMBytes)
	if err != nil {
		return nil, err
	}
	// A fully downloaded file is atomically renamed into the cache, so resuming
	// never treats a partial RPM as a usable artifact.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rpm-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	return b, nil
}

func hashHex(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func parsePrimary(raw []byte) (primaryMD, error) {
	var r io.Reader = strings.NewReader(string(raw))
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		z, err := gzip.NewReader(strings.NewReader(string(raw)))
		if err != nil {
			return primaryMD{}, err
		}
		defer func() { _ = z.Close() }()
		r = io.LimitReader(z, maxMetadataBytes)
	}
	var primary primaryMD
	if err := xml.NewDecoder(r).Decode(&primary); err != nil {
		return primaryMD{}, fmt.Errorf("parse primary XML: %w", err)
	}
	return primary, nil
}

func sortedKeys(m map[string]primaryPackage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func evr(p primaryPackage) string {
	v := p.Version.Ver
	if p.Version.Rel != "" {
		v += "-" + p.Version.Rel
	}
	if p.Version.Epoch != "" && p.Version.Epoch != "0" {
		v = p.Version.Epoch + ":" + v
	}
	return v
}

// immutableMainHeader extracts the RPM main header and reconstructs the
// immutable region that librpm retains in an installed rpmdb. RPM lead is 96
// bytes, followed by a signature header and the main header.
func immutableMainHeader(rpm []byte) ([]byte, error) {
	if len(rpm) < 96+16 || string(rpm[:4]) != "\xed\xab\xee\xdb" {
		return nil, errors.New("invalid RPM lead")
	}
	sigLen, err := headerLength(rpm[96:])
	if err != nil {
		return nil, fmt.Errorf("signature header: %w", err)
	}
	// RPM pads the signature header so the following main header starts on an
	// eight-byte boundary.
	mainAt := 96 + ((sigLen + 7) &^ 7)
	if mainAt > len(rpm) {
		return nil, errors.New("main header offset outside RPM")
	}
	mainLen, err := headerLength(rpm[mainAt:])
	if err != nil {
		return nil, fmt.Errorf("main header: %w", err)
	}
	main := rpm[mainAt : mainAt+mainLen]
	return immutableRegion(main)
}

func headerLength(b []byte) (int, error) {
	if len(b) < 16 || string(b[:4]) != "\x8e\xad\xe8\x01" {
		return 0, errors.New("missing header magic")
	}
	n := int(uint32(b[8])<<24 | uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11]))
	sz := int(uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15]))
	if n < 1 || n > 1<<16 || sz < 16 || sz > 64<<20 || 16+n*16+sz > len(b) {
		return 0, errors.New("invalid header dimensions")
	}
	return 16 + n*16 + sz, nil
}

func immutableRegion(main []byte) ([]byte, error) {
	n := int(uint32(main[8])<<24 | uint32(main[9])<<16 | uint32(main[10])<<8 | uint32(main[11]))
	sz := int(uint32(main[12])<<24 | uint32(main[13])<<16 | uint32(main[14])<<8 | uint32(main[15]))
	entries, data := main[16:16+n*16], main[16+n*16:16+n*16+sz]
	if read32(entries[0:4]) != 63 || read32(entries[4:8]) != 7 || read32(entries[12:16]) != 16 {
		return nil, errors.New("missing immutable region tag")
	}
	trailerAt := int(read32(entries[8:12]))
	if trailerAt < 0 || trailerAt+16 > len(data) {
		return nil, errors.New("immutable region trailer outside data")
	}
	trailer := data[trailerAt : trailerAt+16]
	if read32(trailer[0:4]) != 63 || read32(trailer[4:8]) != 7 || read32(trailer[12:16]) != 16 {
		return nil, errors.New("invalid immutable region trailer")
	}
	indexBytes := -int(int32(read32(trailer[8:12])))
	if indexBytes <= 0 || indexBytes%16 != 0 || indexBytes/16 > n || trailerAt+16 > sz {
		return nil, errors.New("invalid immutable region extent")
	}
	il, dl := indexBytes/16, trailerAt+16
	out := make([]byte, 16+il*16+dl)
	copy(out[:8], main[:8])
	put32(out[8:12], uint32(il))
	put32(out[12:16], uint32(dl))
	copy(out[16:16+il*16], entries[:il*16])
	copy(out[16+il*16:], data[:dl])
	return out, nil
}
func put32(dst []byte, n uint32) {
	dst[0] = byte(n >> 24)
	dst[1] = byte(n >> 16)
	dst[2] = byte(n >> 8)
	dst[3] = byte(n)
}
func read32(src []byte) uint32 {
	return uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
}
