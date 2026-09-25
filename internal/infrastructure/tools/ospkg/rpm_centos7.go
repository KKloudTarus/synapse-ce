package ospkg

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

// CentOS 7's stable signing key is pinned by its full fingerprint, published at
// https://www.centos.org/keys/. This is deliberately outside the scanned rootfs.
const centOS7KeyModulus = "CB0F267E0D01E47131C34121346B40768980045F0A4FBECEBB709E2D9A17BF88C3B254C87D630FEF04817CB1C9BA4FFBCF3797E8A6C2A25BD52C02118A8347A90BACB979DF8D0141D311AEA948E768EC2C850F0B67E0717AD44B326F88333D3E90892AF4CEF753B606014598C010F155BB70E2A34A19E54419EDFCDD65F7A2C4C43C54C4D0E32E31E6F8A4F41F9CAA61A2ABD016EF58B194361559AB20474F777D7883F4D2D3E034ED2BE28B19836327C78C46A7D95ACEE0EC2FBD6841877EC199FD2C4B3AE9B1FC67E24E5A1A974767ABC4C2ED743F26E35D07DAA3A17CD117E7DA0D4B235AEBCD49012A5175B577326306FAE812F81375F0897D1A4880EADCDB9EAABC3329D52C5C84C165B4F968E666D230ABB5C75A78524033C79E3799E3254573A0C76FE19C19BA1FA2F416C4B20D2E8FDB6E3217EDF479E3830F826EE010B24348CE2295319949C0A68FE6D1E45E948E93465EE32BA686A92614361141B85C523CA80A601A45855CD133ADC9B2F89BF36AD8E37F2ADEC20E51DC5963AA6F30E59191D515A33ED6044C53771E4DB465F891D5B942D7101CCFB6921B7AB019C9B2F701258718230014780E6F7517F02CAB999FA4A001429D81E3ADB9FF9C3D1DFF13AF0B66BEFCE129689221CBB5091F93DF233579BA7C98D7C09BF088CD88885CA0F1A5301040D7E54F90382034C18AE0510FE1F226AD86F04929273D8D"

var centOS7Key, centOS7KeyValid = func() (*rsa.PublicKey, bool) {
	n, ok := new(big.Int).SetString(centOS7KeyModulus, 16)
	if !ok {
		return nil, false
	}
	return &rsa.PublicKey{N: n, E: 65537}, true
}()

const (
	rpmTagHeaderImmutable = 63
	rpmTagRSAHeader       = 268
	// RPM's installed database retains header signatures as dribbles. A valid
	// immutable region allows reconstructing exactly the bytes RPM signed.
)

// centOS7SignedIdentity verifies the legacy CentOS 7 RSA/SHA256 v3 OpenPGP
// header signature and returns identity only from its immutable region.
func centOS7SignedIdentity(blob []byte) (name, evr, arch string, ok bool) {
	_, name, evr, arch, ok = centOS7SignedHeader(blob)
	return name, evr, arch, ok
}

func centOS7BaseSignedIdentity(blob []byte) (name, evr, arch string, ok bool) {
	original, _, _, ok := rpmImmutableRegion(blob)
	if !ok {
		return "", "", "", false
	}
	name, evr, arch, ok = parseRPMHeader(original)
	// A digest miss is common in mixed images; check it before public-key work.
	// Membership alone never grants provenance: the signature must also verify.
	if !ok || !centOS7BaseHeaderAllowed(original, name, evr, arch) || !verifyCentOS7RSAHeader(blob, original) {
		return "", "", "", false
	}
	return name, evr, arch, true
}

func centOS7SignedHeader(blob []byte) (original []byte, name, evr, arch string, ok bool) {
	original, _, _, ok = rpmImmutableRegion(blob)
	if !ok || !verifyCentOS7RSAHeader(blob, original) {
		return nil, "", "", "", false
	}
	name, evr, arch, ok = parseRPMHeader(original)
	return original, name, evr, arch, ok
}

func rpmImmutableRegion(blob []byte) (original, entries, data []byte, ok bool) {
	if len(blob) < 8 {
		return nil, nil, nil, false
	}
	n, size := int(binary.BigEndian.Uint32(blob[:4])), int(binary.BigEndian.Uint32(blob[4:8]))
	if n < 1 || n > maxRPMIndex || size < 16 || size > maxRPMData || 8+n*16+size > len(blob) {
		return nil, nil, nil, false
	}
	allEntries := blob[8 : 8+n*16]
	allData := blob[8+n*16 : 8+n*16+size]
	if binary.BigEndian.Uint32(allEntries[:4]) != rpmTagHeaderImmutable || binary.BigEndian.Uint32(allEntries[4:8]) != rpmTypeBin || binary.BigEndian.Uint32(allEntries[12:16]) != 16 {
		return nil, nil, nil, false
	}
	trailerAt := int(binary.BigEndian.Uint32(allEntries[8:12]))
	if trailerAt < 0 || trailerAt+16 > len(allData) {
		return nil, nil, nil, false
	}
	trailer := allData[trailerAt : trailerAt+16]
	if binary.BigEndian.Uint32(trailer[:4]) != rpmTagHeaderImmutable || binary.BigEndian.Uint32(trailer[4:8]) != rpmTypeBin || binary.BigEndian.Uint32(trailer[12:16]) != 16 {
		return nil, nil, nil, false
	}
	regionIndexBytes := -int(int32(binary.BigEndian.Uint32(trailer[8:12])))
	if regionIndexBytes <= 0 || regionIndexBytes%16 != 0 {
		return nil, nil, nil, false
	}
	ril, rdl := regionIndexBytes/16, trailerAt+16
	if ril > n || rdl > size {
		return nil, nil, nil, false
	}
	entries, data = allEntries[:ril*16], allData[:rdl]
	original = make([]byte, 16+len(entries)+len(data))
	copy(original, []byte{0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0})
	binary.BigEndian.PutUint32(original[8:12], uint32(ril))
	binary.BigEndian.PutUint32(original[12:16], uint32(rdl))
	copy(original[16:], entries)
	copy(original[16+len(entries):], data)
	return original, entries, data, true
}

func verifyCentOS7RSAHeader(blob, original []byte) bool {
	if !centOS7KeyValid || len(blob) < 8 {
		return false
	}
	n, size := int(binary.BigEndian.Uint32(blob[:4])), int(binary.BigEndian.Uint32(blob[4:8]))
	if n < 1 || n > maxRPMIndex || size < 1 || size > maxRPMData || 8+n*16+size > len(blob) {
		return false
	}
	entries, data := blob[8:8+n*16], blob[8+n*16:8+n*16+size]
	var sig []byte
	for i := 0; i < len(entries); i += 16 {
		if binary.BigEndian.Uint32(entries[i:i+4]) != rpmTagRSAHeader {
			continue
		}
		if sig != nil || binary.BigEndian.Uint32(entries[i+4:i+8]) != rpmTypeBin {
			return false
		}
		off, count := int(binary.BigEndian.Uint32(entries[i+8:i+12])), int(binary.BigEndian.Uint32(entries[i+12:i+16]))
		if off < 0 || count < 1 || off+count > len(data) {
			return false
		}
		sig = data[off : off+count]
	}
	if len(sig) < 24 || sig[0] != 0x89 || int(binary.BigEndian.Uint16(sig[1:3])) != len(sig)-3 || sig[3] != 3 || sig[4] != 5 || sig[5] != 0 || sig[18] != 1 || sig[19] != 8 {
		return false
	}
	bits := int(binary.BigEndian.Uint16(sig[22:24]))
	bytes := (bits + 7) / 8
	if bits < 512 || bits > centOS7Key.N.BitLen() || 24+bytes != len(sig) || (bits > 0 && sig[24]>>(uint((8-bits%8)%8)) == 0) {
		return false
	}
	// OpenPGP v3 signs the immutable RPM header followed by its five-byte
	// type/timestamp trailer. The packet's issuer key id is intentionally ignored.
	h := sha256.New()
	_, _ = h.Write(original)
	_, _ = h.Write(sig[5:10])
	digest := h.Sum(nil)
	if sig[20] != digest[0] || sig[21] != digest[1] {
		return false
	}
	rsaSig := make([]byte, (centOS7Key.N.BitLen()+7)/8)
	copy(rsaSig[len(rsaSig)-bytes:], sig[24:])
	return rsa.VerifyPKCS1v15(centOS7Key, crypto.SHA256, digest, rsaSig) == nil
}
