# TLS test fixtures — NOT secrets

`cert.pem` and `key.pem` are a throwaway self-signed P-256 certificate
and its private key, generated with the openssl CLI solely for the TLS
tests under `src/tls/` (DESIGN.md §4) — `Credentials.load` parses them,
and the engine tests drive a handshake with them. The
private key is committed **on purpose**: it signs nothing but these
in-memory test handshakes, is trusted by nothing, and must never be
reused anywhere. Regenerate freely:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -subj "/CN=spike.zoxy.test" \
  -addext "subjectAltName=DNS:spike.zoxy.test" -days 3650 -out cert.pem
```

`rsa2048-key.pem` is a throwaway RSA key with no certificate of its own,
and it exists to be **refused**: zssl signs RSA-PSS, zoxy does not accept
an RSA leaf (an RSA sign is ~1-2 ms on the loop that is sized for a
~260 µs ECDSA handshake), and `Credentials.load` is what says no. It
pairs with `cert.pem` in that test because nothing checks that a key
matches its certificate before the key is classified — the point is the
key. Same warning as above: committed on purpose, trusted by nothing.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out rsa2048-key.pem
```

## Origin trust fixtures (§7, TLS to an HTTP/2 origin)

A small PKI for the verifier that checks an origin's chain, valid 2019 to
2049 so the simulator's wall clock (2020 onward) sits inside it:

- `origin-ca.pem`: a P-256 CA (`CA:TRUE`), the trust anchor. Its key was
  deleted once it had signed the leaf; nothing more is ever issued from it.
- `origin-cert.pem` and `origin-key.pem`: the leaf it signed, for
  `DNS:origin.zoxy.test`, `CA:FALSE`, and its key, which a test origin
  serves with.
- `other-ca.pem`: an unrelated CA, to be the anchor a chain does *not*
  reach.
- `rogue-cert.pem`: a certificate for `DNS:victim.zoxy.test` signed by the
  *leaf's* key. The leaf is not a CA, so a chain through it must be
  refused even though every signature in it verifies.

Same warning as above: throwaway, committed on purpose, trusted by
nothing outside these tests.

```sh
openssl ecparam -name prime256v1 -genkey -noout -out origin-ca-key.pem
openssl req -new -x509 -key origin-ca-key.pem -subj "/CN=zoxy test origin CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -not_before 20190101000000Z -not_after 20490101000000Z -out origin-ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out origin-key.pem
openssl req -new -key origin-key.pem -subj "/CN=origin.zoxy.test" -out leaf.csr
openssl x509 -req -in leaf.csr -CA origin-ca.pem -CAkey origin-ca-key.pem \
  -set_serial 2 -not_before 20190101000000Z -not_after 20490101000000Z \
  -extfile leaf.ext -out origin-cert.pem   # leaf.ext: CA:FALSE, the SAN, serverAuth
```
