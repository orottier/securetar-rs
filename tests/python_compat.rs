use std::{
    cmp,
    fs::File,
    io::{Cursor, Read, Result as IoResult},
    path::Path,
};

use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};

const PASSWORD: &str = "hunter2";

#[test]
fn decrypts_v3_tar_written_by_python_securetar() -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = encrypted_payload()?;

    let stream = SecureTarDecryptStream::new(
        Cursor::new(encrypted),
        SecureTarRootKeyContext::new(PASSWORD),
    )?;
    let decoded = read_hello_txt(stream)?;

    assert_eq!(decoded, "hello from python securetar\n");
    Ok(())
}

#[test]
fn decrypts_when_source_returns_short_reads() -> Result<(), Box<dyn std::error::Error>> {
    let encrypted = encrypted_payload()?;

    let stream = SecureTarDecryptStream::new(
        ShortRead::new(Cursor::new(encrypted), 5_496),
        SecureTarRootKeyContext::new(PASSWORD),
    )?;
    let decoded = read_hello_txt(stream)?;

    assert_eq!(decoded, "hello from python securetar\n");
    Ok(())
}

fn encrypted_payload() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let outer_tar = manifest.join("tests/fixtures/python_v3_outer.tar");
    assert!(outer_tar.is_file(), "missing Python SecureTar fixture");

    let mut outer = tar::Archive::new(File::open(outer_tar)?);
    let mut encrypted = Vec::new();
    for entry in outer.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() == Path::new("payload.tar") {
            entry.read_to_end(&mut encrypted)?;
            break;
        }
    }
    assert!(!encrypted.is_empty());

    Ok(encrypted)
}

fn read_hello_txt(stream: impl Read) -> Result<String, Box<dyn std::error::Error>> {
    let mut inner = tar::Archive::new(stream);
    let mut decoded = String::new();
    for entry in inner.entries()? {
        let mut entry = entry?;
        if entry.path()?.ends_with("hello.txt") {
            entry.read_to_string(&mut decoded)?;
            break;
        }
    }

    Ok(decoded)
}

struct ShortRead<R> {
    inner: R,
    max_read: usize,
}

impl<R> ShortRead<R> {
    fn new(inner: R, max_read: usize) -> Self {
        Self { inner, max_read }
    }
}

impl<R: Read> Read for ShortRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let len = cmp::min(buf.len(), self.max_read);
        self.inner.read(&mut buf[..len])
    }
}
