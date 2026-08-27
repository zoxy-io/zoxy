# net/testdata

`client_hello_openssl.bin` — one real TLS ClientHello, captured from
`openssl s_client -servername real.example.com` (OpenSSL 3.6.2) against a
socket that recorded its first read and closed.

It is here because `client_hello.zig`'s other tests build their input from
the same understanding of the format that the parser encodes, so they
cannot catch a misreading of the spec — only a disagreement with itself. A
byte string this repository did not author can.

1547 bytes, one record. Its size is the point as much as its shape: a
modern hello offering post-quantum key shares (X25519MLKEM768) is far past
the few hundred bytes a ClientHello used to be, which is what
`constants.client_hello_bytes_max` and the loader's relay-buffer floor are
sized against.
