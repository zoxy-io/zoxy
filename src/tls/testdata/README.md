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
