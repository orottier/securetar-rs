use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};

const PASSWORD: &str = "hunter2";

#[test]
fn decrypts_v3_tar_written_by_python_securetar() -> Result<(), Box<dyn std::error::Error>> {
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

    let stream = SecureTarDecryptStream::new(
        Cursor::new(encrypted),
        SecureTarRootKeyContext::new(PASSWORD),
    )?;
    let mut inner = tar::Archive::new(stream);
    let mut decoded = String::new();
    for entry in inner.entries()? {
        let mut entry = entry?;
        if entry.path()?.ends_with("hello.txt") {
            entry.read_to_string(&mut decoded)?;
            break;
        }
    }

    assert_eq!(decoded, "hello from python securetar\n");
    Ok(())
}
