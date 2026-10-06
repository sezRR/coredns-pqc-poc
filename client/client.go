// Package client provides the demo's explicit DNS UDP-to-TCP fallback.
package client

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

type Result struct {
	Message   *dns.Msg
	UsedTCP   bool
	UDPBytes  int
	WireBytes int // DNS message only; excludes TCP's two-byte length prefix
}

// Exchange starts over UDP and retries the same question over TCP on TC=1.
// miekg/dns does not perform this fallback automatically.
func Exchange(ctx context.Context, server string, question *dns.Msg) (*Result, error) {
	if question == nil || len(question.Question) != 1 {
		return nil, errors.New("exactly one DNS question required")
	}
	message, size, err := exchangeWire(ctx, "udp", server, question)
	if err != nil {
		return nil, fmt.Errorf("UDP query: %w", err)
	}
	result := &Result{Message: message, UDPBytes: size}
	if message.Truncated {
		message, size, err = exchangeWire(ctx, "tcp", server, question)
		if err != nil {
			return nil, fmt.Errorf("TCP fallback: %w", err)
		}
		result.Message, result.UsedTCP = message, true
	}
	if message.Truncated || message.Rcode != dns.RcodeSuccess || !message.Response ||
		message.Id != question.Id || len(message.Question) != 1 || len(question.Question) != 1 ||
		message.Question[0] != question.Question[0] {
		return nil, errors.New("incomplete, unsuccessful, or mismatched DNS response")
	}
	result.WireBytes = size
	return result, nil
}

// Read the payload before decoding: Msg.Unpack does not retain compression
// layout, so repacking it cannot accurately measure received wire bytes.
func exchangeWire(ctx context.Context, network, server string, question *dns.Msg) (*dns.Msg, int, error) {
	transport := &dns.Client{Net: network, Timeout: 3 * time.Second}
	conn, err := transport.DialContext(ctx, server)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, 0, err
	}
	if opt := question.IsEdns0(); opt != nil && opt.UDPSize() >= 512 {
		conn.UDPSize = opt.UDPSize()
	}
	if err := conn.WriteMsg(question); err != nil {
		return nil, 0, err
	}
	for {
		wire, err := conn.ReadMsgHeader(nil) // excludes TCP's length prefix
		if err != nil {
			return nil, 0, err
		}
		message := new(dns.Msg)
		if err := message.Unpack(wire); err != nil {
			return nil, 0, err
		}
		if message.Id != question.Id {
			if network == "udp" {
				continue // same behavior as dns.Client.ExchangeContext
			}
			return nil, 0, dns.ErrId
		}
		return message, len(wire), nil
	}
}

// RRSet extracts the requested data and exactly one covering RRSIG. The
// verifier never accepts a bare answer, even if a server supplies the AD bit.
func RRSet(message *dns.Msg, name string, typeCode uint16) ([]dns.RR, *dns.RRSIG, error) {
	var records []dns.RR
	var signature *dns.RRSIG
	for _, rr := range message.Answer {
		if dns.CanonicalName(rr.Header().Name) != dns.CanonicalName(name) || rr.Header().Class != dns.ClassINET {
			continue
		}
		if rr.Header().Rrtype == typeCode {
			records = append(records, rr)
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == typeCode {
			if signature != nil {
				return nil, nil, errors.New("multiple covering signatures are unsupported in this demo")
			}
			signature = sig
		}
	}
	if len(records) == 0 || signature == nil {
		return nil, nil, errors.New("answer lacks the requested RRset or its RRSIG")
	}
	return records, signature, nil
}
