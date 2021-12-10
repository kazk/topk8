# topk8

Convert private keys to PKCS#8 format in pure Rust.

The following formats are supported at the moment:

- PKCS#1 PEM (`RSA PRIVATE KEY`)
- SEC1 PEM (`EC PRIVATE KEY`)

## TODO

- Test against OpenSSL
- Upgrade `rsa` when [RustCrypto/RSA#120](https://github.com/RustCrypto/RSA/issues/120) is resolved to avoid duplicate crates (`der`, `pkcs8`)
