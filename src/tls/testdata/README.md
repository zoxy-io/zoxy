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

`rsa2048-key.pem` and `rsa2048-cert.pem` are a throwaway RSA-2048 key and
its self-signed certificate (#411), for `DNS:rsa.zoxy.test` and also
`DNS:spike.zoxy.test`, the ECDSA fixture's name, so one name has both key
types behind it. The engine tests and the smoke gate use them to check
that ECDSA is chosen wherever a client can verify it, and that an RSA-PSS
handshake completes where it cannot.

`rsa4096-key.pem` and `rsa4096-cert.pem` are the largest RSA key zoxy
admits, for `DNS:rsa4096.zoxy.test`. They exist so `zig build
tls-heap-proof` can price the costliest key against
`libcrypto_heap_bytes_per_certificate`. Same warning as above: committed
on purpose, trusted by nothing.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out rsa2048-key.pem
openssl req -new -x509 -key rsa2048-key.pem -subj "/CN=rsa.zoxy.test" \
  -addext "subjectAltName=DNS:rsa.zoxy.test,DNS:spike.zoxy.test" \
  -days 3650 -sha256 -out rsa2048-cert.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
  -out rsa4096-key.pem
openssl req -new -x509 -key rsa4096-key.pem -subj "/CN=rsa4096.zoxy.test" \
  -addext "subjectAltName=DNS:rsa4096.zoxy.test" -days 3650 -out rsa4096-cert.pem
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
- The same leaf and key are also the second certificate a listener
  chooses by SNI (#297): the engine test and the smoke gate name
  `origin.zoxy.test` and check it is the one presented, which they can
  because `cert.pem` above covers another name.
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

## Client trust fixtures (#304, mutual TLS on a listener)

The same shape for the other direction, valid 2019 to 2049:

- `client-ca.pem`: a P-256 CA (`CA:TRUE`) a listener's `client_ca` trusts.
  Its key was deleted once it had signed the leaf.
- `client-cert.pem` and `client-key.pem`: the client leaf it signed,
  `CN=client.zoxy.test`, `CA:FALSE`, `extendedKeyUsage=clientAuth`, and
  its key, which a test client presents. Its SHA-256 fingerprint is
  `F1FD192CFF76490BAF1534F777226E96DBB03D9751A657648E0955116D0D4FCB`.

`other-ca.pem` above serves as the anchor a client chain does *not*
reach, and `origin-ca.pem` as a CA certificate presented as a client,
which must be refused for being a CA. Same warning: throwaway, committed
on purpose, trusted by nothing outside these tests.

```sh
openssl ecparam -name prime256v1 -genkey -noout -out client-ca-key.pem
openssl req -new -x509 -key client-ca-key.pem -subj "/CN=zoxy test client CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -not_before 20190101000000Z -not_after 20490101000000Z -out client-ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out client-key.pem
openssl req -new -key client-key.pem -subj "/CN=client.zoxy.test" -out leaf.csr
openssl x509 -req -in leaf.csr -CA client-ca.pem -CAkey client-ca-key.pem \
  -set_serial 2 -not_before 20190101000000Z -not_after 20490101000000Z \
  -extfile leaf.ext -out client-cert.pem   # leaf.ext: CA:FALSE, clientAuth
```
