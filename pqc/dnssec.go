// Package pqc implements ML-DSA-44 DNSSEC using IANA algorithm 18.
// It deliberately supports only the record types used by this demo.
package pqc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

const (
	// IANA MLDSA44, referencing draft-westerbaan-dnssec-mldsa-03.
	Algorithm uint8 = 18
	TTL             = 300
)

// DNSKEY encodes the raw 1312-byte ML-DSA-44 public key without any prefix.
func DNSKEY(zone string, public *mldsa44.PublicKey) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr:   dns.RR_Header{Name: dns.CanonicalName(dns.Fqdn(zone)), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: TTL},
		Flags: dns.ZONE | dns.SEP, Protocol: 3, Algorithm: Algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(public.Bytes()),
	}
}

func decodeField(encoded string, size int) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}
	if len(data) != size {
		return nil, fmt.Errorf("incorrect ML-DSA-44 field length: got %d, want %d", len(data), size)
	}
	return data, nil
}

func publicKey(key *dns.DNSKEY) (*mldsa44.PublicKey, error) {
	if key == nil || key.Algorithm != Algorithm || key.Protocol != 3 || key.Flags&dns.ZONE == 0 || key.Flags&dns.REVOKE != 0 || key.Hdr.Rrtype != dns.TypeDNSKEY {
		return nil, errors.New("invalid ML-DSA-44 zone DNSKEY")
	}
	data, err := decodeField(key.PublicKey, mldsa44.PublicKeySize)
	if err != nil {
		return nil, err
	}
	public := new(mldsa44.PublicKey)
	return public, public.UnmarshalBinary(data)
}

// MatchDS authenticates a DNSKEY against a locally provisioned SHA-256 DS.
// A self-signed DNSKEY obtained over the network is not itself a trust anchor.
func MatchDS(key *dns.DNSKEY, anchor *dns.DS) error {
	if _, err := publicKey(key); err != nil {
		return err
	}
	if anchor == nil || anchor.Hdr.Rrtype != dns.TypeDS || anchor.DigestType != dns.SHA256 ||
		anchor.Hdr.Class != key.Hdr.Class || dns.CanonicalName(anchor.Hdr.Name) != dns.CanonicalName(key.Hdr.Name) {
		return errors.New("invalid or mismatched DS trust anchor")
	}
	ds := key.ToDS(dns.SHA256)
	if ds == nil || ds.KeyTag != anchor.KeyTag || ds.Algorithm != anchor.Algorithm || !strings.EqualFold(ds.Digest, anchor.Digest) {
		return errors.New("DNSKEY does not match pinned DS trust anchor")
	}
	return nil
}

// Sign signs RFC 4034 canonical RRSIG metadata and RRset bytes using pure
// ML-DSA-44 with an empty context. No external prehash is applied.
func Sign(private *mldsa44.PrivateKey, key *dns.DNSKEY, rrset []dns.RR, now time.Time) (*dns.RRSIG, error) {
	if private == nil || len(rrset) == 0 {
		return nil, errors.New("private key and nonempty RRset required")
	}
	public, err := publicKey(key)
	if err != nil {
		return nil, err
	}
	if !public.Equal(private.Public()) {
		return nil, errors.New("DNSKEY does not match private key")
	}
	h := rrset[0].Header()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: h.Name, Rrtype: dns.TypeRRSIG, Class: h.Class, Ttl: h.Ttl},
		TypeCovered: h.Rrtype, Algorithm: Algorithm, Labels: uint8(dns.CountLabel(h.Name)),
		OrigTtl: h.Ttl, Inception: uint32(now.Add(-5 * time.Minute).Unix()),
		Expiration: uint32(now.Add(24 * time.Hour).Unix()), KeyTag: key.KeyTag(), SignerName: key.Hdr.Name,
	}
	data, err := signedData(key, sig, rrset)
	if err != nil {
		return nil, err
	}
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(private, data, nil, true, signature); err != nil {
		return nil, err
	}
	sig.Signature = base64.StdEncoding.EncodeToString(signature)
	return sig, nil
}

// Verify checks metadata, validity time, and the ML-DSA-44 signature. The caller
// must first authenticate key against an out-of-band trust anchor.
func Verify(key *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR, now time.Time) error {
	public, err := publicKey(key)
	if err != nil {
		return err
	}
	if sig == nil || !sig.ValidityPeriod(now) {
		return errors.New("missing, expired, or not-yet-valid RRSIG")
	}
	data, err := signedData(key, sig, rrset)
	if err != nil {
		return err
	}
	signature, err := decodeField(sig.Signature, mldsa44.SignatureSize)
	if err != nil {
		return err
	}
	if !mldsa44.Verify(public, data, nil, signature) {
		return errors.New("ML-DSA-44 signature verification failed")
	}
	return nil
}

func signedData(key *dns.DNSKEY, sig *dns.RRSIG, rrset []dns.RR) ([]byte, error) {
	if len(rrset) == 0 {
		return nil, errors.New("empty RRset")
	}
	owner := dns.CanonicalName(rrset[0].Header().Name)
	if sig.Algorithm != Algorithm || sig.KeyTag != key.KeyTag() || sig.Hdr.Rrtype != dns.TypeRRSIG ||
		dns.CanonicalName(sig.SignerName) != dns.CanonicalName(key.Hdr.Name) ||
		!dns.IsSubDomain(key.Hdr.Name, owner) || sig.Hdr.Class != key.Hdr.Class ||
		dns.CanonicalName(sig.Hdr.Name) != owner || sig.Labels != uint8(dns.CountLabel(owner)) ||
		strings.HasPrefix(owner, "*.") {
		return nil, errors.New("RRSIG/DNSKEY metadata mismatch (wildcards are unsupported)")
	}

	// RRSIG RDATA, excluding its Signature field (RFC 4034 section 3.1.8.1).
	data := binary.BigEndian.AppendUint16(nil, sig.TypeCovered)
	data = append(data, sig.Algorithm, sig.Labels)
	data = binary.BigEndian.AppendUint32(data, sig.OrigTtl)
	data = binary.BigEndian.AppendUint32(data, sig.Expiration)
	data = binary.BigEndian.AppendUint32(data, sig.Inception)
	data = binary.BigEndian.AppendUint16(data, sig.KeyTag)
	name := make([]byte, 255)
	n, err := dns.PackDomainName(dns.CanonicalName(sig.SignerName), name, 0, nil, false)
	if err != nil {
		return nil, err
	}
	data = append(data, name[:n]...)

	type record struct{ wire, rdata []byte }
	records := make([]record, 0, len(rrset))
	for _, rr := range rrset {
		copy := dns.Copy(rr)
		h := copy.Header()
		if dns.CanonicalName(h.Name) != owner || h.Class != sig.Hdr.Class || h.Rrtype != sig.TypeCovered {
			return nil, errors.New("inconsistent RRset")
		}
		h.Name, h.Ttl = owner, sig.OrigTtl
		switch r := copy.(type) {
		case *dns.A, *dns.AAAA, *dns.DNSKEY:
		case *dns.NS:
			r.Ns = dns.CanonicalName(r.Ns)
		case *dns.SOA:
			r.Ns, r.Mbox = dns.CanonicalName(r.Ns), dns.CanonicalName(r.Mbox)
		default:
			return nil, fmt.Errorf("unsupported RR type %d", h.Rrtype)
		}
		wire := make([]byte, dns.Len(copy)+1)
		n, err := dns.PackRR(copy, wire, 0, nil, false)
		if err != nil {
			return nil, err
		}
		_, offset, err := dns.UnpackDomainName(wire[:n], 0)
		if err != nil {
			return nil, err
		}
		records = append(records, record{wire[:n], wire[offset+10 : n]})
	}
	// Sort by RDATA, not by the complete RR (which contains RDLENGTH).
	sort.Slice(records, func(i, j int) bool { return bytes.Compare(records[i].rdata, records[j].rdata) < 0 })
	for i, record := range records {
		if i == 0 || !bytes.Equal(record.rdata, records[i-1].rdata) {
			data = append(data, record.wire...)
		}
	}
	return data, nil
}
