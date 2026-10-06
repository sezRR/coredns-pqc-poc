// Package keys provisions local demo key material separately from source code.
package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"coredns-pqc/pqc"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

const SeedFile = "mldsa44.seed"

// LoadPrivate reads a random 32-byte ML-DSA seed, not a legacy Dilithium key.
func LoadPrivate(path string) (*mldsa44.PrivateKey, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(seed) != mldsa44.SeedSize {
		return nil, fmt.Errorf("seed must contain exactly %d bytes", mldsa44.SeedSize)
	}
	_, private := mldsa44.NewKeyFromSeed((*[mldsa44.SeedSize]byte)(seed))
	return private, nil
}

// Ensure reuses an existing seed or creates one with OS entropy. Public
// anchors are created once; a mismatch fails rather than changing trust.
func Ensure(privateDir, publicDir, zone string) (*dns.DNSKEY, error) {
	for _, dir := range []string{privateDir, publicDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}
	path := filepath.Join(privateDir, SeedFile)
	private, err := LoadPrivate(path)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, mldsa44.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := writeNew(path, seed, 0600); err != nil {
			return nil, err
		}
		private, err = LoadPrivate(path)
	}
	if err != nil {
		return nil, err
	}
	key := pqc.DNSKEY(zone, private.Public().(*mldsa44.PublicKey))
	ds := key.ToDS(dns.SHA256)
	if ds == nil {
		return nil, errors.New("cannot derive DS trust anchor")
	}
	for name, content := range map[string]string{"trust-anchor.ds": ds.String() + "\n", "dnskey.zone": key.String() + "\n"} {
		path := filepath.Join(publicDir, name)
		existing, err := os.ReadFile(path)
		if err == nil {
			if string(existing) != content {
				return nil, fmt.Errorf("%s differs from the signing key; refusing to overwrite trust material", path)
			}
			continue
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := writeNew(path, []byte(content), 0644); err != nil {
			return nil, err
		}
	}
	return key, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	return errors.Join(writeErr, closeErr)
}
