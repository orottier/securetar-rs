# Changelog

## Version 0.1.0 (2026-06-07)

- Initial release of Rust reader primitives for SecureTar v3 encrypted streams.
- Added SecureTar v3 header parsing, password validation, key restoration, and
  XChaCha20-Poly1305 secretstream decryption.
- Added compatibility coverage for Python-generated SecureTar fixtures.
