package main

import (
	_ "coredns-pqc/plugin/pqc"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/log"
)

func main() {
	// This is a lean custom CoreDNS distribution, not a fork. Only imported
	// plugins are available; keep middleware before the authoritative plugin.
	dnsserver.Directives = []string{"bind", "errors", "log", "pqc"}
	coremain.Run()
}
