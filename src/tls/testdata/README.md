# Spike test fixtures — NOT secrets

`cert.der` and `scalar.hex` are a throwaway self-signed P-256 certificate
and its raw private scalar, generated with the openssl CLI solely for
`src/tls/spike_test.zig` (Phase 3a, PLANS.md). The private key is
committed **on purpose**: it signs nothing but this in-memory test
handshake, is trusted by nothing, and must never be reused anywhere.
Regenerate freely:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -subj "/CN=spike.zoxy.test" \
  -addext "subjectAltName=DNS:spike.zoxy.test" -days 3650 \
  -outform DER -out cert.der
# raw 32-byte scalar (low 64 hex chars strips DER sign-padding)
openssl ec -in key.pem -text -noout \
  | awk '/priv:/{f=1;next} /pub:/{f=0} f' | tr -d ' :\n' \
  | tail -c 64 > scalar.hex
rm key.pem
```
