package keys

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"coredns-pqc/pqc"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

// MigrateFrom253 updates only this demo's matching legacy public records.
// It never writes the private seed or accepts an unrelated trust anchor.
func MigrateFrom253(privateDir, publicDir, zone string) (*dns.DNSKEY, error) {
	private, err := LoadPrivate(filepath.Join(privateDir, SeedFile))
	if err != nil {
		return nil, err
	}
	public := private.Public().(*mldsa44.PublicKey)
	key := pqc.DNSKEY(zone, public)
	legacy := dns.Copy(key).(*dns.DNSKEY)
	legacy.Algorithm = dns.PRIVATEDNS
	legacy.PublicKey = base64.StdEncoding.EncodeToString(append([]byte("\x07mldsa44\x03pqc\x04test\x00"), public.Bytes()...))
	legacyDS, currentDS := legacy.ToDS(dns.SHA256), key.ToDS(dns.SHA256)
	if legacyDS == nil || currentDS == nil {
		return nil, errors.New("cannot derive DS trust anchor for migration")
	}
	records := []struct {
		name         string
		old, current dns.RR
		existing     []byte
	}{
		{name: "dnskey.zone", old: legacy, current: key},
		{name: "trust-anchor.ds", old: legacyDS, current: currentDS},
	}
	// Validate every file before replacing any of them. Refuse unknown data,
	// including records for a different private key or a different zone.
	for i := range records {
		r := &records[i]
		path := filepath.Join(publicDir, r.name)
		r.existing, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if string(r.existing) != r.old.String()+"\n" && string(r.existing) != r.current.String()+"\n" {
			return nil, fmt.Errorf("%s is not a matching algorithm-253 or algorithm-18 record; refusing migration", path)
		}
		backup, err := os.ReadFile(path + ".algorithm253.bak")
		if err == nil && string(backup) != r.old.String()+"\n" {
			return nil, fmt.Errorf("%s.algorithm253.bak already contains different data", path)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	for _, r := range records {
		current := []byte(r.current.String() + "\n")
		if bytes.Equal(r.existing, current) {
			continue // migration is idempotent, including after partial failure
		}
		path := filepath.Join(publicDir, r.name)
		if err := backupPublic(path+".algorithm253.bak", r.existing); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := replacePublic(path, current); err != nil {
			return nil, err
		}
	}
	return key, nil
}

func replacePublic(path string, data []byte) error {
	temporary, err := writePublicTemp(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	return os.Rename(temporary, path)
}

// Link a completed temporary file into place atomically without overwriting
// an existing backup. A failed write never publishes a partial final backup.
func backupPublic(path string, data []byte) error {
	temporary, err := writePublicTemp(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)
	return os.Link(temporary, path)
}

func writePublicTemp(path string, data []byte) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return "", err
	}
	writeErr := file.Chmod(0644)
	if writeErr == nil {
		_, writeErr = file.Write(data)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		os.Remove(file.Name())
		return "", err
	}
	return file.Name(), nil
}
