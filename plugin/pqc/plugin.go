// Package pqc is a small authoritative CoreDNS plugin for a PQC DNSSEC lab.
package pqc

import (
	"context"
	"errors"
	"net"
	"time"

	"coredns-pqc/pqc"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

type Handler struct {
	zone    string
	private *mldsa44.PrivateKey
	key     *dns.DNSKEY
	maxUDP  uint16
	records map[string]map[uint16][]dns.RR
}

// New creates the demo's fixed, positive-answer zone. Unsupported names/types
// are refused: this plugin does not claim to provide NSEC denial proofs.
func New(zone string, private *mldsa44.PrivateKey, maxUDP uint16) (*Handler, error) {
	zone = dns.CanonicalName(dns.Fqdn(zone))
	if _, ok := dns.IsDomainName(zone); !ok || zone == "." || private == nil || maxUDP < 512 || maxUDP > 1232 {
		return nil, errors.New("valid non-root zone, private key, and max_udp in 512..1232 required")
	}
	key := pqc.DNSKEY(zone, private.Public().(*mldsa44.PublicKey))
	h := &Handler{zone: zone, private: private, key: key, maxUDP: maxUDP, records: make(map[string]map[uint16][]dns.RR)}
	add := func(rr dns.RR) {
		name, kind := rr.Header().Name, rr.Header().Rrtype
		if h.records[name] == nil {
			h.records[name] = make(map[uint16][]dns.RR)
		}
		h.records[name][kind] = append(h.records[name][kind], rr)
	}
	header := func(name string, kind uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: kind, Class: dns.ClassINET, Ttl: pqc.TTL}
	}
	add(key)
	add(&dns.SOA{Hdr: header(zone, dns.TypeSOA), Ns: "ns." + zone, Mbox: "hostmaster." + zone,
		Serial: 1, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: pqc.TTL})
	add(&dns.NS{Hdr: header(zone, dns.TypeNS), Ns: "ns." + zone})
	add(&dns.A{Hdr: header("ns."+zone, dns.TypeA), A: net.ParseIP("192.0.2.53")})
	add(&dns.A{Hdr: header("www."+zone, dns.TypeA), A: net.ParseIP("192.0.2.44")})
	return h, nil
}

func (h *Handler) Name() string { return "pqc" }

func (h *Handler) ServeDNS(_ context.Context, w dns.ResponseWriter, request *dns.Msg) (int, error) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.Compress = true
	opt := request.IsEdns0()
	if opt != nil {
		response.SetEdns0(h.maxUDP, opt.Do())
	}
	switch {
	case request.Opcode != dns.OpcodeQuery:
		response.Rcode = dns.RcodeNotImplemented
	case len(request.Question) != 1:
		response.Rcode = dns.RcodeFormatError
	case opt != nil && opt.Version() != 0:
		response.Rcode = dns.RcodeBadVers
	default:
		q := request.Question[0]
		rrset := h.records[dns.CanonicalName(q.Name)][q.Qtype]
		if q.Qclass != dns.ClassINET || len(rrset) == 0 {
			response.Rcode = dns.RcodeRefused
			break
		}
		response.Authoritative = true
		for _, rr := range rrset {
			response.Answer = append(response.Answer, dns.Copy(rr))
		}
		if opt != nil && opt.Do() {
			sig, err := pqc.Sign(h.private, h.key, rrset, time.Now())
			if err != nil {
				return dns.RcodeServerFailure, err
			}
			response.Answer = append(response.Answer, sig)
		}
	}
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
		limit := uint16(512)
		if opt != nil && opt.UDPSize() > limit {
			limit = opt.UDPSize()
		}
		if limit > h.maxUDP {
			limit = h.maxUDP
		}
		wire, err := response.Pack()
		if err != nil {
			return dns.RcodeServerFailure, err
		}
		if len(wire) > int(limit) {
			// Never split an RR or return part of the signed RRset. Keep the
			// question and OPT, set TC, and let the client retry over TCP.
			response.Answer, response.Ns = nil, nil
			response.Truncated = true
		}
	}
	// CoreDNS treats REFUSED/FORMERR/NOTIMP return codes as "not written".
	// The actual wire RCODE is already in response; report handled here.
	return dns.RcodeSuccess, w.WriteMsg(response)
}
