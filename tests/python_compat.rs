use std::{
    fs::{self, File},
    io::{Cursor, Read},
    path::Path,
    process::Command,
};

use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};

const PASSWORD: &str = "hunter2";

#[test]
fn decrypts_v3_tar_written_by_python_securetar() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let python_securetar = manifest.join("../../securetar");
    if !python_securetar.join("securetar/__init__.py").is_file() {
        eprintln!("skipping: upstream Python securetar checkout not found");
        return Ok(());
    }

    let temp = tempfile::tempdir()?;
    let input = temp.path().join("input");
    fs::create_dir(&input)?;
    fs::write(input.join("hello.txt"), b"hello from python securetar\n")?;
    let outer_tar = temp.path().join("outer.tar");

    let script = r#"
from pathlib import Path
import sys
from securetar import SecureTarArchive, atomic_contents_add

out = Path(sys.argv[1])
source = Path(sys.argv[2])
password = sys.argv[3]

with SecureTarArchive(out, "w", password=password, create_version=3) as archive:
    with archive.create_tar("payload.tar", gzip=False) as inner:
        atomic_contents_add(inner, source, file_filter=lambda _: False, arcname=".")
"#;

    let output = Command::new("python3")
        .env("PYTHONPATH", &python_securetar)
        .arg("-c")
        .arg(script)
        .arg(&outer_tar)
        .arg(&input)
        .arg(PASSWORD)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("ModuleNotFoundError") {
            eprintln!("skipping: Python securetar dependencies unavailable: {stderr}");
            return Ok(());
        }
        panic!("Python securetar failed: {stderr}");
    }

    let mut outer = tar::Archive::new(File::open(&outer_tar)?);
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
