package pqc

import (
	"strconv"

	"coredns-pqc/internal/keys"
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("pqc", setup) }

func setup(c *caddy.Controller) error {
	var handler *Handler
	for c.Next() {
		if handler != nil {
			return plugin.Error("pqc", plugin.ErrOnce)
		}
		args := c.RemainingArgs()
		if len(args) != 2 {
			return plugin.Error("pqc", c.ArgErr())
		}
		maxUDP := uint64(1232)
		for c.NextBlock() {
			if c.Val() != "max_udp" {
				return plugin.Error("pqc", c.Errf("unknown option %q", c.Val()))
			}
			values := c.RemainingArgs()
			if len(values) != 1 {
				return plugin.Error("pqc", c.ArgErr())
			}
			value, err := strconv.ParseUint(values[0], 10, 16)
			if err != nil || value < 512 || value > 1232 {
				return plugin.Error("pqc", c.Err("max_udp must be in 512..1232"))
			}
			maxUDP = value
		}
		private, err := keys.LoadPrivate(args[1])
		if err != nil {
			return plugin.Error("pqc", err)
		}
		handler, err = New(args[0], private, uint16(maxUDP))
		if err != nil {
			return plugin.Error("pqc", err)
		}
	}
	if handler == nil {
		return plugin.Error("pqc", c.ArgErr())
	}
	dnsserver.GetConfig(c).AddPlugin(func(_ plugin.Handler) plugin.Handler { return handler })
	return nil
}
