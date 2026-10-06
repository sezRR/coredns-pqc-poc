package main

import (
	"flag"
	"fmt"
	"log"

	"coredns-pqc/internal/keys"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

func main() {
	privateDir := flag.String("private-dir", "keys/private", "directory for the private seed")
	publicDir := flag.String("public-dir", "keys/public", "directory for DNSKEY and DS trust anchor")
	zone := flag.String("zone", "pqc.test.", "demo zone")
	migrate := flag.Bool("migrate-from-253", false, "upgrade matching legacy public records to algorithm 18; preserve seed and back up old records")
	flag.Parse()
	var key *dns.DNSKEY
	var err error
	if *migrate {
		key, err = keys.MigrateFrom253(*privateDir, *publicDir, *zone)
	} else {
		key, err = keys.Ensure(*privateDir, *publicDir, *zone)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ML-DSA-44 key ready: zone=%s algorithm=%d key-tag=%d public-key=%d signature=%d bytes\n",
		key.Hdr.Name, key.Algorithm, key.KeyTag(), mldsa44.PublicKeySize, mldsa44.SignatureSize)
	fmt.Printf("Trust anchor: %s/trust-anchor.ds (provision locally, not from DNS)\n", *publicDir)
}
