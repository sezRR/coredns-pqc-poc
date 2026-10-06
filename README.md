# CoreDNS + ML-DSA-44 DNSSEC lab

A Go demo for OrbStack / Docker Compose: a custom CoreDNS plugin signs real
DNSKEY and data RRsets with Cloudflare CIRCL's **ML-DSA-44** implementation,
and a custom verifier authenticates them against a locally provisioned DS.

**A lab, not a production authoritative server.** This uses IANA-assigned
algorithm **18 (`MLDSA44`)**, following the wire format in
`draft-westerbaan-dnssec-mldsa-03`. Validators need explicit ML-DSA-44 support;
an assigned number alone does not add support to older resolvers or libraries.
`dig` can display records and demonstrate fallback, but does not verify these
signatures. The included Go verifier performs that verification.

## Run on OrbStack

With OrbStack running and its Docker context selected:

```sh
docker context show                         # normally: orbstack
make demo
```

Or without Make:

```sh
docker compose up --build -d --wait coredns
docker compose run --rm verifier
```

This builds a lean CoreDNS distribution, provisions a random key once, exposes
**both UDP and TCP on `127.0.0.1:1053`**, and runs verification plus a tampering
check. Go is only needed on the host if you want to run the tests or host tools;
the container build supplies Go 1.26.6.

The verifier reports:

```text
pqc.test. DNSKEY: UDP ... bytes TC=1 -> TCP ... bytes TC=0
DNSKEY verified against local SHA-256 DS: algorithm=18 key-tag=...
www.pqc.test. A: UDP ... bytes TC=1 -> TCP ... bytes TC=0
VALID: www.pqc.test. A, ML-DSA-44 (1312-byte key, 2420-byte signature)
PASS: tampered signed data rejected
```

Use another host port if 1053 is occupied:

```sh
DNS_PORT=5300 make demo
```

`make down` stops this project but preserves its key and trust-anchor volumes.
Do not delete just one volume: the private key and public anchor must match.
Keygen refuses to silently overwrite mismatched trust material.

### Upgrade an existing algorithm-253 demo

The private seed can stay the same, but changing the DNSKEY algorithm and
encoding changes its key tag and DS digest. Upgrade the public records before
starting the new server:

```sh
docker compose build
docker compose stop coredns
docker compose run --rm --no-deps keygen -private-dir /private -public-dir /public -migrate-from-253
make demo
```

Migration checks that **both** old public records match the existing private
key and zone before changing either file. It preserves the seed and saves the
old records as `dnskey.zone.algorithm253.bak` and
`trust-anchor.ds.algorithm253.bak`. It is safe to repeat after migration.
Unrelated anchors are refused, not replaced. Any host copies of the Compose
trust anchor must be copied again using the command below.

For existing native-mode keys, run this once before `make keys`:

```sh
go run ./cmd/keygen -private-dir keys/native/private -public-dir keys/native/public -migrate-from-253
```

## See UDP → TCP fallback with dig

```sh
# Keep the truncated UDP response instead of retrying.
dig @127.0.0.1 -p 1053 www.pqc.test A +dnssec +bufsize=1232 +ignore

# Normal retry: dig prints "Truncated, retrying in TCP mode".
dig @127.0.0.1 -p 1053 www.pqc.test A +dnssec +bufsize=1232

# A DNSKEY plus its RRSIG is larger still.
dig @127.0.0.1 -p 1053 pqc.test DNSKEY +dnssec +tcp

# Without DO, this small A response fits over UDP and has no RRSIG.
dig @127.0.0.1 -p 1053 www.pqc.test A +nodnssec
```

ML-DSA-44's raw public key is **1,312 bytes** and its signature **2,420 bytes**.
They are encoded directly, without an algorithm-253 identifier prefix. A signed
answer therefore exceeds the conservative **1,232-byte EDNS UDP budget**. Some larger
UDP datagrams are technically possible; the cap avoids relying on IP
fragmentation. TCP carries the full DNS message with standard DNS framing.

The server respects a smaller client budget (512 bytes without EDNS), never
exceeds its configured cap even when the client advertises 4096, and returns
`TC=1` without partial RRsets when the answer would be too large.

## Trust and signing

```text
keygen (OS entropy)
  ├── signing_keys volume: private 32-byte seed → CoreDNS only
  └── trust_anchors volume: DNSKEY + SHA-256 DS → verifier only

verifier --UDP/DO--> CoreDNS --TC=1--> verifier
verifier ----TCP---> CoreDNS --DNSKEY/RRSIG--> verifier
  1. Match DNSKEY to the local DS, including its digest, not just key tag.
  2. Verify the DNSKEY RRset's self-signature using the authenticated key.
  3. Fetch and verify the requested data RRset, checking signature times.
```

The DS is provisioned locally, **not fetched over the same DNS connection**.
A self-signed key fetched from an untrusted server would not establish trust.
This is a single-zone trust anchor, not a delegation chain from the public root.

DNSKEY Public Key contains exactly **1,312 raw bytes**, and RRSIG Signature
contains exactly **2,420 raw bytes**. DNSKEY, RRSIG, and DS all use algorithm
**18**. There is no private-algorithm domain-name prefix. `.test` remains the
reserved domain used for the isolated demo zone.

Signatures cover the canonical RRSIG metadata followed by canonical, sorted
RRset wire bytes (RFC 4034). CIRCL uses pure ML-DSA-44 with an empty context and
randomized signing; there is no extra external prehash. This is the FIPS 204
ML-DSA implementation, not CIRCL's older Dilithium package.

## Demo zone and limits

| Owner | Types |
| --- | --- |
| `pqc.test.` | DNSKEY, SOA, NS |
| `ns.pqc.test.` | A (`192.0.2.53`) |
| `www.pqc.test.` | A (`192.0.2.44`) |

The documentation-range IPs are answer data; they are not upstream resolvers.
Set DO (`+dnssec`) to request RRSIGs. DNSKEY itself is available without DO.
The authoritative server never asserts AD; the custom client verifies locally.

Scope is **positive signed answers**. There is no recursion, delegation-chain
validation, NSEC/NSEC3 authenticated denial, wildcard expansion, key rollover,
AXFR, or production key management. Unsupported names/types (including ANY and
direct RRSIG queries) return REFUSED rather than insecure NXDOMAIN/NODATA.
Signing is online per request, suitable for a small lab, not a public service.
The Compose ports bind only to localhost; keep them that way.

## Other verification queries

Overriding a Compose command replaces its defaults, so include the server and
trust-anchor flags:

```sh
docker compose run --rm verifier -server coredns:1053 -trust-anchor /trust/trust-anchor.ds -name pqc.test. -type SOA -tamper
docker compose run --rm verifier -server coredns:1053 -trust-anchor /trust/trust-anchor.ds -udp-size 512
```

To use the host Go verifier against the Compose server, copy **only the public
anchor** from this project's local keygen container:

```sh
mkdir -p keys/public
docker compose cp keygen:/public/trust-anchor.ds keys/public/trust-anchor.ds
go run ./cmd/verify -server 127.0.0.1:1053 -tamper
```

Do not run `make keys` for this mode: it generates a separate host key, which
will not match the Compose server. For a separate native-Go run:

```sh
make down  # free port 1053 first; Compose keys are preserved
make keys
go run ./cmd/coredns -conf Corefile.local
# In another terminal:
make verify
```

Native mode uses `keys/native/`, separate from the Compose anchor copy in
`keys/public/`. `Corefile.local` binds only to `127.0.0.1` and uses the
host-generated seed. Host keys are gitignored and
excluded from Docker builds. Neither host nor Compose keys are rotated on
ordinary restarts.

## Tests and files

```sh
make test    # full suite with the race detector
make vet
```

Tests exercise the two public boundaries: DNSSEC signing/verification and live
DNS transport. They cover wire round trips, tampering, substituted keys,
signature validity and metadata, canonicalization checked independently against
miekg/dns, UDP budgets, DO behavior, and complete signed answers after TCP retry.

- `plugin/pqc/`: custom authoritative plugin and Corefile setup.
- `pqc/`: algorithm-18 DNSKEY/RRSIG encoding, signing, verification, DS matching.
- `client/`: explicit UDP-first/TCP-fallback client and signed-RRset extraction.
- `cmd/coredns/`, `cmd/keygen/`, `cmd/verify/`: runnable Go tools.
- `compose.yaml`, `Dockerfile`, `Corefile`: OrbStack-compatible container demo.

References: [CIRCL](https://github.com/cloudflare/circl),
[CoreDNS external plugins](https://coredns.io/explugins/),
[IANA DNSSEC algorithm registry](https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml),
[ML-DSA DNSSEC specification (work in progress)](https://www.ietf.org/archive/id/draft-westerbaan-dnssec-mldsa-03.html),
[RFC 4034](https://www.rfc-editor.org/rfc/rfc4034),
[RFC 4035](https://www.rfc-editor.org/rfc/rfc4035),
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
