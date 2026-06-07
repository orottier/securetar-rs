# securetar

Rust reader primitives for SecureTar v3 encrypted streams.

This crate is an independent Rust implementation aligned with the Python
[`home-assistant-libs/securetar`](https://github.com/home-assistant-libs/securetar)
package. It keeps the Python package's Apache-2.0 license, follows the v3
format and constants, and uses upstream-compatible fixtures for behavior checks.

`ha-backup-extractor` uses this crate, but the crate is intended to stand on
its own for any code that needs to read SecureTar v3 content.

## Supported Scope

- SecureTar v3 header parsing and serialization
- password validation
- Argon2id + BLAKE2b key restoration
- XChaCha20-Poly1305 secretstream decryption
- validation behavior for truncated, missing-final-tag, and early-final-tag streams
- constants aligned with the Python package where useful for compatibility

Legacy SecureTar v1/v2 AES-CBC and archive writing helpers are intentionally not
implemented yet.

## Example

```rust,no_run
use std::{fs::File, io::Read};

use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};

let file = File::open("encrypted.securetar")?;
let context = SecureTarRootKeyContext::new("password");
let mut stream = SecureTarDecryptStream::new(file, context)?;

let mut plaintext = Vec::new();
stream.read_to_end(&mut plaintext)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

If a caller has already consumed part of the SecureTar header while sniffing a
stream, use `SecureTarDecryptStream::with_prefix`.
