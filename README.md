# securetar

Rust reader primitives for SecureTar v3 encrypted streams.

This crate is an AI-assisted Rust port of the Python
[`home-assistant-libs/securetar`](https://github.com/home-assistant-libs/securetar)
package.

## Supported features

- SecureTar v3 header parsing and serialization
- password validation
- Argon2id + BLAKE2b key restoration
- XChaCha20-Poly1305 secretstream decryption
- validation behavior for truncated, missing-final-tag, and early-final-tag streams
- constants aligned with the Python package where useful for compatibility

Legacy SecureTar v1/v2 AES-CBC and archive _writing_ helpers are intentionally
not supported.

## Example

```rust,no_run
use std::{fs::File, io::Read};

use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};

let file = File::open("encrypted.securetar")?;
let context = SecureTarRootKeyContext::new("password");
let mut stream = SecureTarDecryptStream::new(file, context)?;

let mut plaintext = Vec::new();
stream.read_to_end(&mut plaintext)?;
// Ok::<(), Box<dyn std::error::Error>>(())
```

If a caller has already consumed part of the SecureTar header while sniffing a
stream, use `SecureTarDecryptStream::with_prefix`.
