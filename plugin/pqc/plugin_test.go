package pqc_test

import (
	"context"
	"net"
	"testing"
	"time"

	"coredns-pqc/client"
	pqcplugin "coredns-pqc/plugin/pqc"
	"coredns-pqc/pqc"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

func startServer(t *testing.T) (string, *dns.DNSKEY) {
	t.Helper()
	public, private, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := pqcplugin.New("pqc.test.", private, 1232)
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	serve := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if code, err := handler.ServeDNS(context.Background(), w, r); err != nil {
			t.Errorf("ServeDNS: %v", err)
		} else if code != dns.RcodeSuccess {
			t.Errorf("written response must signal CoreDNS not to write again, got status %d", code)
		}
	})
	for _, server := range []*dns.Server{{Listener: tcp, Handler: serve}, {PacketConn: udp, Handler: serve}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		t.Cleanup(func() {
			if err := server.Shutdown(); err != nil {
				t.Error(err)
			}
		})
		go func() {
			if err := server.ActivateAndServe(); err != nil {
				t.Errorf("DNS server: %v", err)
			}
		}()
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("DNS server did not start")
		}
	}
	return tcp.Addr().String(), pqc.DNSKEY("pqc.test.", public)
}

func TestUDPBudgetAndUnsignedAnswers(t *testing.T) {
	server, _ := startServer(t)
	for _, tc := range []struct {
		name          string
		kind          uint16
		budget        uint16
		do, truncated bool
	}{
		{"512 byte signed A", dns.TypeA, 512, true, true},
		{"undersized EDNS", dns.TypeA, 128, true, true},
		{"large EDNS capped at 1232", dns.TypeA, 4096, true, true},
		{"unsigned A fits", dns.TypeA, 1232, false, false},
		{"unsigned A without EDNS", dns.TypeA, 0, false, false},
		{"DNSKEY without EDNS exceeds 512", dns.TypeDNSKEY, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := "www.pqc.test."
			if tc.kind == dns.TypeDNSKEY {
				name = "pqc.test."
			}
			q := new(dns.Msg)
			q.SetQuestion(name, tc.kind)
			if tc.budget != 0 {
				q.SetEdns0(tc.budget, tc.do)
			}
			response, _, err := (&dns.Client{Net: "udp", Timeout: time.Second}).Exchange(q, server)
			if err != nil {
				t.Fatal(err)
			}
			limit := int(tc.budget)
			if limit < 512 {
				limit = 512
			}
			if limit > 1232 {
				limit = 1232
			}
			if response.Truncated != tc.truncated || response.Len() > limit {
				t.Fatalf("wrong truncation/budget: TC=%v, bytes=%d, limit=%d", response.Truncated, response.Len(), limit)
			}
			if !tc.truncated && (len(response.Answer) != 1 || response.AuthenticatedData) {
				t.Fatalf("expected unsigned authoritative A, without AD: %v", response)
			}
		})
	}
}

func TestUnsupportedAnswersAreRefusedNotInsecureDenials(t *testing.T) {
	server, _ := startServer(t)
	q := new(dns.Msg)
	q.SetQuestion("missing.pqc.test.", dns.TypeA)
	q.SetEdns0(1232, true)
	r, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(q, server)
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeRefused || len(r.Answer) != 0 || r.Authoritative {
		t.Fatalf("expected REFUSED, got %v", r)
	}
}

func TestLargeSignedAnswersRetryFromUDPToTCP(t *testing.T) {
	server, key := startServer(t)
	for _, q := range []struct {
		name     string
		typeCode uint16
	}{{"pqc.test.", dns.TypeDNSKEY}, {"www.pqc.test.", dns.TypeA}} {
		t.Run(dns.TypeToString[q.typeCode], func(t *testing.T) {
			request := new(dns.Msg)
			request.SetQuestion(q.name, q.typeCode)
			request.SetEdns0(1232, true)
			udp := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
			truncated, _, err := udp.Exchange(request, server)
			if err != nil {
				t.Fatal(err)
			}
			if !truncated.Truncated || len(truncated.Answer) != 0 || truncated.Len() > 1232 {
				t.Fatalf("expected small TC=1 UDP answer, got %v", truncated)
			}
			result, err := client.Exchange(context.Background(), server, request)
			if err != nil {
				t.Fatal(err)
			}
			if !result.UsedTCP || result.Message.Truncated || !result.Message.Authoritative || result.WireBytes <= 1232 {
				t.Fatalf("expected complete large TCP answer: %+v", result)
			}
			// This test server explicitly compresses replies. The measurement
			// must count those bytes, not an uncompressed decoded Msg.Len().
			compressed := result.Message.Copy()
			compressed.Compress = true
			wire, err := compressed.Pack()
			if err != nil {
				t.Fatal(err)
			}
			if result.WireBytes != len(wire) {
				t.Fatalf("received-byte count = %d, compressed wire = %d", result.WireBytes, len(wire))
			}
			rrset, sig, err := client.RRSet(result.Message, q.name, q.typeCode)
			if err != nil {
				t.Fatal(err)
			}
			if sig.Algorithm != 18 {
				t.Fatalf("network RRSIG algorithm = %d, want MLDSA44 (18)", sig.Algorithm)
			}
			if q.typeCode == dns.TypeDNSKEY && rrset[0].(*dns.DNSKEY).Algorithm != 18 {
				t.Fatal("network DNSKEY does not use MLDSA44 (18)")
			}
			if err := pqc.Verify(key, sig, rrset, time.Now()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
