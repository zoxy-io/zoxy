# TLS test fixtures — NOT secrets

`cert.pem` and `key.pem` are a throwaway self-signed P-256 certificate
and its private key, generated with the openssl CLI solely for the TLS
tests under `src/tls/` (Phase 3a, PLANS.md) — `Credentials.load` parses
them, and the engine/heap-proof tests drive a handshake with them. The
private key is committed **on purpose**: it signs nothing but these
in-memory test handshakes, is trusted by nothing, and must never be
reused anywhere. Regenerate freely:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -subj "/CN=spike.zoxy.test" \
  -addext "subjectAltName=DNS:spike.zoxy.test" -days 3650 -out cert.pem
```
