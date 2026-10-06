package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"coredns-pqc/client"
	"coredns-pqc/pqc"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

func main() {
	server := flag.String("server", "127.0.0.1:1053", "authoritative server host:port")
	anchorPath := flag.String("trust-anchor", "keys/public/trust-anchor.ds", "locally provisioned DS trust anchor")
	name := flag.String("name", "www.pqc.test.", "name to verify")
	typeName := flag.String("type", "A", "RR type to verify: A, NS, SOA, or DNSKEY")
	udpSize := flag.Uint("udp-size", 1232, "advertised EDNS UDP size (512..65535)")
	tamper := flag.Bool("tamper", false, "alter the answer locally and require verification to reject it")
	probe := flag.Bool("probe", false, "healthcheck only: query the unsigned demo A record")
	flag.Parse()
	log.SetFlags(0)
	if *udpSize < 512 || *udpSize > 65535 {
		log.Fatal("udp-size must be in 512..65535")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if *probe {
		q := new(dns.Msg)
		q.SetQuestion("www.pqc.test.", dns.TypeA)
		r, err := client.Exchange(ctx, *server, q)
		if err != nil {
			log.Fatal(err)
		}
		if !r.Message.Authoritative || len(r.Message.Answer) != 1 {
			log.Fatal("probe did not receive the expected authoritative answer")
		}
		return
	}
	if err := run(ctx, *server, *anchorPath, dns.Fqdn(*name), strings.ToUpper(*typeName), uint16(*udpSize), *tamper); err != nil {
		log.Fatal(err)
	}
}

func query(ctx context.Context, server, name string, kind, udpSize uint16) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(name, kind)
	q.RecursionDesired = false
	q.SetEdns0(udpSize, true)
	r, err := client.Exchange(ctx, server, q)
	if err != nil {
		return nil, err
	}
	if !r.Message.Authoritative {
		return nil, fmt.Errorf("server returned a non-authoritative answer")
	}
	if r.UsedTCP {
		fmt.Printf("%s %s: UDP %d bytes TC=1 -> TCP %d bytes TC=0\n", name, dns.TypeToString[kind], r.UDPBytes, r.WireBytes)
	} else {
		fmt.Printf("%s %s: UDP %d bytes TC=0\n", name, dns.TypeToString[kind], r.WireBytes)
	}
	return r.Message, nil
}

func run(ctx context.Context, server, anchorPath, name, typeName string, udpSize uint16, tamper bool) error {
	kind, ok := dns.StringToType[typeName]
	if !ok || (kind != dns.TypeA && kind != dns.TypeNS && kind != dns.TypeSOA && kind != dns.TypeDNSKEY) {
		return fmt.Errorf("unsupported demo RR type %q", typeName)
	}
	data, err := os.ReadFile(anchorPath)
	if err != nil {
		return fmt.Errorf("read local trust anchor: %w", err)
	}
	rr, err := dns.NewRR(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("parse local trust anchor: %w", err)
	}
	anchor, ok := rr.(*dns.DS)
	if !ok {
		return fmt.Errorf("trust anchor must be a DS record")
	}
	keyMessage, err := query(ctx, server, anchor.Hdr.Name, dns.TypeDNSKEY, udpSize)
	if err != nil {
		return err
	}
	keySet, keySig, err := client.RRSet(keyMessage, anchor.Hdr.Name, dns.TypeDNSKEY)
	if err != nil {
		return err
	}
	var trusted *dns.DNSKEY
	for _, rr := range keySet {
		key := rr.(*dns.DNSKEY)
		if pqc.MatchDS(key, anchor) == nil {
			trusted = key
			break
		}
	}
	if trusted == nil {
		return fmt.Errorf("no DNSKEY matches the pinned DS trust anchor")
	}
	if err := pqc.Verify(trusted, keySig, keySet, time.Now()); err != nil {
		return fmt.Errorf("DNSKEY RRset verification: %w", err)
	}
	fmt.Printf("DNSKEY verified against local SHA-256 DS: algorithm=%d key-tag=%d\n", trusted.Algorithm, trusted.KeyTag())
	message, err := query(ctx, server, name, kind, udpSize)
	if err != nil {
		return err
	}
	rrset, sig, err := client.RRSet(message, name, kind)
	if err != nil {
		return err
	}
	if err := pqc.Verify(trusted, sig, rrset, time.Now()); err != nil {
		return fmt.Errorf("answer verification: %w", err)
	}
	fmt.Printf("VALID: %s %s, ML-DSA-44 (%d-byte key, %d-byte signature)\n", name, typeName, mldsa44.PublicKeySize, mldsa44.SignatureSize)
	if tamper {
		// Change signed metadata, which works for every supported RR type.
		changed := dns.Copy(sig).(*dns.RRSIG)
		changed.OrigTtl++
		if err := pqc.Verify(trusted, changed, rrset, time.Now()); err == nil {
			return fmt.Errorf("tampering was incorrectly accepted")
		}
		fmt.Println("PASS: tampered signed data rejected")
	}
	return nil
}
