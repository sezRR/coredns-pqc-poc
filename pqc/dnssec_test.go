package pqc_test

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"coredns-pqc/pqc"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

func TestSignedRRSetSurvivesDNSWireRoundTrip(t *testing.T) {
	_, private, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := pqc.DNSKEY("pqc.test.", private.Public().(*mldsa44.PublicKey))
	if key.Algorithm != 18 {
		t.Fatalf("DNSKEY algorithm = %d, want IANA MLDSA44 (18)", key.Algorithm)
	}
	encodedKey, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(encodedKey) != 1312 {
		t.Fatalf("DNSKEY must contain the raw 1312-byte ML-DSA-44 key, got %d bytes: %v", len(encodedKey), err)
	}
	rrset := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.pqc.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP("192.0.2.44"),
	}}
	now := time.Now()
	sig, err := pqc.Sign(private, key, rrset, now)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Algorithm != 18 {
		t.Fatalf("RRSIG algorithm = %d, want IANA MLDSA44 (18)", sig.Algorithm)
	}
	encodedSignature, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil || len(encodedSignature) != 2420 {
		t.Fatalf("RRSIG must contain the raw 2420-byte ML-DSA-44 signature, got %d bytes: %v", len(encodedSignature), err)
	}
	if ds := key.ToDS(dns.SHA256); ds == nil || ds.Algorithm != 18 {
		t.Fatalf("DS must use MLDSA44 (18), got %v", ds)
	}
	message := &dns.Msg{Answer: append(rrset, sig, key)}
	wire, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var decoded dns.Msg
	if err := decoded.Unpack(wire); err != nil {
		t.Fatal(err)
	}
	if err := pqc.Verify(decoded.Answer[2].(*dns.DNSKEY), decoded.Answer[1].(*dns.RRSIG), decoded.Answer[:1], now); err != nil {
		t.Fatalf("valid ML-DSA-44 RRSIG rejected: %v", err)
	}
}

// Use miekg/dns's existing Ed25519 path as an independent RFC 4034 encoder.
// Only the algorithm octet changes; the remaining DNSSEC signed bytes must
// match. This catches sign/verify sharing the same canonicalization mistake.
func TestSignaturesMatchIndependentRFC4034Encoding(t *testing.T) {
	seed := [mldsa44.SeedSize]byte{1, 2, 3} // test fixture, never a demo key
	public, private := mldsa44.NewKeyFromSeed(&seed)
	key := pqc.DNSKEY("pqc.test.", public)
	now := time.Now()
	for _, text := range [][]string{
		{"WWW.pqc.test. 300 IN A 192.0.2.99", "WWW.pqc.test. 300 IN A 192.0.2.44"},
		{"www.pqc.test. 300 IN AAAA 2001:db8::44"},
		{"pqc.test. 300 IN NS Longer.pqc.test.", "pqc.test. 300 IN NS NS.pqc.test."},
		{"pqc.test. 300 IN SOA NS.pqc.test. Hostmaster.pqc.test. 1 3600 600 86400 300"},
		{key.String()},
	} {
		var rrset []dns.RR
		for _, text := range text {
			rr, err := dns.NewRR(text)
			if err != nil {
				t.Fatal(err)
			}
			rrset = append(rrset, rr)
		}
		t.Run(dns.TypeToString[rrset[0].Header().Rrtype], func(t *testing.T) {
			sig, err := pqc.Sign(private, key, rrset, now)
			if err != nil {
				t.Fatal(err)
			}
			reference := dns.Copy(sig).(*dns.RRSIG)
			reference.Algorithm = dns.ED25519
			capture := &capturingSigner{private: ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))}
			if err := reference.Sign(capture, rrset); err != nil {
				t.Fatal(err)
			}
			capture.message[2] = pqc.Algorithm // RRSIG algorithm octet (RFC 4034)
			encoded, err := base64.StdEncoding.DecodeString(sig.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if len(encoded) != 2420 {
				t.Fatal("incorrect ML-DSA-44 signature length")
			}
			if !mldsa44.Verify(public, capture.message, nil, encoded) {
				t.Fatal("ML-DSA signature does not cover independently encoded RFC 4034 bytes")
			}
			// Cached TTLs, case-insensitive names, and RR order must not affect validation.
			var cached []dns.RR
			for i := len(rrset) - 1; i >= 0; i-- {
				rr := dns.Copy(rrset[i])
				rr.Header().Ttl = 42
				rr.Header().Name = dns.CanonicalName(rr.Header().Name)
				cached = append(cached, rr)
			}
			if err := pqc.Verify(key, sig, cached, now); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type capturingSigner struct {
	private ed25519.PrivateKey
	message []byte
}

func (s *capturingSigner) Public() crypto.PublicKey { return s.private.Public() }
func (s *capturingSigner) Sign(random io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.message = append([]byte(nil), message...)
	return s.private.Sign(random, message, opts)
}

func TestTrustAnchorRejectsSubstitutedKey(t *testing.T) {
	public, _, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := pqc.DNSKEY("pqc.test.", public)
	anchor := key.ToDS(dns.SHA256)
	if err := pqc.MatchDS(key, anchor); err != nil {
		t.Fatalf("trusted key rejected: %v", err)
	}
	otherPublic, _, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pqc.MatchDS(pqc.DNSKEY("pqc.test.", otherPublic), anchor); err == nil {
		t.Fatal("substituted key accepted against pinned DS")
	}
}

func TestAlgorithm18MatchesDraftTrustAnchorVector(t *testing.T) {
	// Section 6 of draft-westerbaan-dnssec-mldsa-03: seed 00..1f,
	// owner example.com., DNSKEY flags 257, protocol 3, algorithm 18.
	var seed [mldsa44.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	public, _ := mldsa44.NewKeyFromSeed(&seed)
	key := pqc.DNSKEY("example.com.", public)
	if key.KeyTag() != 59829 {
		t.Fatalf("draft key tag = %d, want 59829", key.KeyTag())
	}
	ds := key.ToDS(dns.SHA256)
	want := "812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa"
	if ds == nil || ds.Algorithm != 18 || !strings.EqualFold(ds.Digest, want) {
		t.Fatalf("DS does not match the independently published draft vector: %v", ds)
	}
	legacy := dns.Copy(key).(*dns.DNSKEY)
	legacy.Algorithm = 253
	if err := pqc.MatchDS(key, legacy.ToDS(dns.SHA256)); err == nil {
		t.Fatal("algorithm-253 anchor accepted for algorithm-18 DNSKEY")
	}
}

func TestVerificationRejectsTamperingAndInvalidMetadata(t *testing.T) {
	public, private, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key := pqc.DNSKEY("pqc.test.", public)
	rr := &dns.A{Hdr: dns.RR_Header{Name: "www.pqc.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.44")}
	now := time.Now()
	sig, err := pqc.Sign(private, key, []dns.RR{rr}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*dns.DNSKEY, *dns.RRSIG, *dns.A) time.Time
	}{
		{"answer", func(_ *dns.DNSKEY, _ *dns.RRSIG, r *dns.A) time.Time { r.A = net.ParseIP("192.0.2.99"); return now }},
		{"signature", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time {
			data, _ := base64.StdEncoding.DecodeString(s.Signature)
			data[len(data)-1] ^= 1
			s.Signature = base64.StdEncoding.EncodeToString(data)
			return now
		}},
		{"legacy private signature prefix", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time {
			data, _ := base64.StdEncoding.DecodeString(s.Signature)
			s.Signature = base64.StdEncoding.EncodeToString(append([]byte("\x07mldsa44\x03pqc\x04test\x00"), data...))
			return now
		}},
		{"legacy algorithm", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time { s.Algorithm = 253; return now }},
		{"legacy private key prefix", func(k *dns.DNSKEY, _ *dns.RRSIG, _ *dns.A) time.Time {
			data, _ := base64.StdEncoding.DecodeString(k.PublicKey)
			k.PublicKey = base64.StdEncoding.EncodeToString(append([]byte("\x07mldsa44\x03pqc\x04test\x00"), data...))
			return now
		}},
		{"key protocol", func(k *dns.DNSKEY, _ *dns.RRSIG, _ *dns.A) time.Time { k.Protocol = 2; return now }},
		{"zone flag", func(k *dns.DNSKEY, _ *dns.RRSIG, _ *dns.A) time.Time { k.Flags = dns.SEP; return now }},
		{"algorithm", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time { s.Algorithm = dns.ED25519; return now }},
		{"key tag", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time { s.KeyTag++; return now }},
		{"signer", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time { s.SignerName = "other.test."; return now }},
		{"labels", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time { s.Labels--; return now }},
		{"original TTL", func(_ *dns.DNSKEY, s *dns.RRSIG, _ *dns.A) time.Time { s.OrigTtl++; return now }},
		{"expired", func(_ *dns.DNSKEY, _ *dns.RRSIG, _ *dns.A) time.Time { return now.Add(25 * time.Hour) }},
		{"not yet valid", func(_ *dns.DNSKEY, _ *dns.RRSIG, _ *dns.A) time.Time { return now.Add(-time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, s, r := dns.Copy(key).(*dns.DNSKEY), dns.Copy(sig).(*dns.RRSIG), dns.Copy(rr).(*dns.A)
			at := tc.mutate(k, s, r)
			if err := pqc.Verify(k, s, []dns.RR{r}, at); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}
