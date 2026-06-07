//! SecureTar v3 reader primitives.
//!
//! This crate is an independent Rust implementation aligned with the Python
//! [`home-assistant-libs/securetar`](https://github.com/home-assistant-libs/securetar)
//! package. It currently implements the SecureTar v3 read path: header parsing,
//! password validation, key restoration, and streaming decryption.
//!
//! Legacy SecureTar v1/v2 AES-CBC and archive-writing helpers are intentionally
//! not implemented yet.

use std::io::{Cursor, Read};

use argon2::{Algorithm, Argon2, Params, Version};
use sodiumoxide::crypto::secretstream::xchacha20poly1305 as secretstream;
use thiserror::Error;

pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_IV_SIZE: usize = AES_BLOCK_SIZE;

pub const V3_SECRETSTREAM_ABYTES: usize = 17;
pub const V3_SECRETSTREAM_CHUNK_SIZE: u64 = 1024 * 1024;
pub const V3_KDF_OPSLIMIT: u32 = 8;
pub const V3_KDF_MEMLIMIT: u32 = 16 * 1024 * 1024;
pub const V3_DERIVED_KEY_SIZE: usize = 32;
pub const V3_DERIVED_KEY_SALT_SIZE: usize = 16;
pub const V3_CHACHA20_HEADER_SIZE: usize = 24;

pub const DEFAULT_BUFSIZE: usize = 10240;

pub const SECURETAR_MAGIC: &[u8] = b"SecureTar";
pub const SECURETAR_MAGIC_RESERVED: [u8; 6] = [0; 6];

pub const SECURETAR_LEGACY_HEADER_SIZE: usize = AES_IV_SIZE;
pub const SECURETAR_FILE_ID_SIZE: usize = 16;
pub const SECURETAR_FILE_METADATA_SIZE: usize = 16;
pub const SECURETAR_V2_CIPHER_INIT_SIZE: usize = AES_IV_SIZE;
pub const SECURETAR_V2_HEADER_SIZE: usize =
    SECURETAR_FILE_ID_SIZE + SECURETAR_FILE_METADATA_SIZE + SECURETAR_V2_CIPHER_INIT_SIZE;
pub const SECURETAR_V3_CIPHER_INIT_SIZE: usize = 104;
pub const SECURETAR_V3_HEADER_SIZE: usize =
    SECURETAR_FILE_ID_SIZE + SECURETAR_FILE_METADATA_SIZE + SECURETAR_V3_CIPHER_INIT_SIZE;

pub const GZIP_MAGIC_BYTES: &[u8] = b"\x1f\x8b\x08";
pub const TAR_MAGIC_BYTES: &[u8] = b"ustar";
pub const TAR_MAGIC_OFFSET: usize = 257;
pub const TAR_BLOCK_SIZE: usize = 512;

pub const DEFAULT_CIPHER_VERSION: u8 = 3;

const V3_VERSION: u8 = 3;
const V3_PERSONALIZATION: &[u8; 11] = b"SecureTarv3";

#[derive(Debug, Error)]
pub enum SecureTarError {
    #[error("Unsupported SecureTar version: {0}")]
    UnsupportedVersion(u8),

    #[error("Invalid reserved bytes in SecureTar header")]
    InvalidReservedBytes,

    #[error("Plaintext size is required")]
    MissingPlaintextSize,

    #[error("Invalid SecureTar header")]
    InvalidHeader,

    #[error("Invalid password")]
    InvalidPassword,

    #[error("Unexpected final tag in secretstream decryption")]
    UnexpectedFinalTag,

    #[error("Missing final tag in secretstream decryption")]
    MissingFinalTag,

    #[error("Ciphertext is too short")]
    CiphertextTooShort,

    #[error("Unexpected failure")]
    SecretStreamFailure,

    #[error("failed to initialize sodiumoxide")]
    SodiumInit,

    #[error("failed to derive SecureTar v3 root key: {0}")]
    KeyDerivation(String),

    #[error("{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SecureTarError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Encrypt,
    Decrypt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureTarHeader {
    cipher_initialization: Vec<u8>,
    plaintext_size: Option<u64>,
    version: u8,
}

impl SecureTarHeader {
    pub fn new(
        cipher_initialization: impl Into<Vec<u8>>,
        plaintext_size: Option<u64>,
        version: u8,
    ) -> Result<Self> {
        match version {
            1 | 2 => Err(SecureTarError::UnsupportedVersion(version)),
            3 => Ok(Self {
                cipher_initialization: cipher_initialization.into(),
                plaintext_size,
                version,
            }),
            _ => Err(SecureTarError::UnsupportedVersion(version)),
        }
    }

    pub fn from_reader(reader: &mut impl Read) -> Result<Self> {
        let mut file_id = [0; SECURETAR_FILE_ID_SIZE];
        reader.read_exact(&mut file_id)?;
        Self::from_file_id_and_reader(file_id, reader)
    }

    pub fn from_prefix_and_reader(prefix: &[u8], reader: &mut impl Read) -> Result<Self> {
        if prefix.len() > SECURETAR_FILE_ID_SIZE {
            return Err(SecureTarError::InvalidHeader);
        }

        let mut file_id = [0; SECURETAR_FILE_ID_SIZE];
        file_id[..prefix.len()].copy_from_slice(prefix);
        reader.read_exact(&mut file_id[prefix.len()..])?;
        Self::from_file_id_and_reader(file_id, reader)
    }

    fn from_file_id_and_reader(
        file_id: [u8; SECURETAR_FILE_ID_SIZE],
        reader: &mut impl Read,
    ) -> Result<Self> {
        let magic = &file_id[..SECURETAR_MAGIC.len()];
        if magic != SECURETAR_MAGIC {
            return Err(SecureTarError::UnsupportedVersion(1));
        }

        let version = file_id[SECURETAR_MAGIC.len()];
        if version != V3_VERSION {
            return Err(SecureTarError::UnsupportedVersion(version));
        }
        if file_id[10..16] != SECURETAR_MAGIC_RESERVED {
            return Err(SecureTarError::InvalidReservedBytes);
        }

        let mut metadata = [0; SECURETAR_FILE_METADATA_SIZE];
        reader.read_exact(&mut metadata)?;
        let plaintext_size = u64::from_be_bytes(
            metadata[..8]
                .try_into()
                .map_err(|_| SecureTarError::InvalidHeader)?,
        );

        let mut cipher_initialization = vec![0; SECURETAR_V3_CIPHER_INIT_SIZE];
        reader.read_exact(&mut cipher_initialization)?;

        Ok(Self {
            cipher_initialization,
            plaintext_size: Some(plaintext_size),
            version,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let plaintext_size = self
            .plaintext_size
            .ok_or(SecureTarError::MissingPlaintextSize)?;
        if self.version != V3_VERSION {
            return Err(SecureTarError::UnsupportedVersion(self.version));
        }
        if self.cipher_initialization.len() != SECURETAR_V3_CIPHER_INIT_SIZE {
            return Err(SecureTarError::InvalidHeader);
        }

        let mut bytes = Vec::with_capacity(SECURETAR_V3_HEADER_SIZE);
        bytes.extend_from_slice(SECURETAR_MAGIC);
        bytes.push(self.version);
        bytes.extend_from_slice(&SECURETAR_MAGIC_RESERVED);
        bytes.extend_from_slice(&plaintext_size.to_be_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&self.cipher_initialization);
        Ok(bytes)
    }

    pub fn cipher_initialization(&self) -> &[u8] {
        &self.cipher_initialization
    }

    pub fn plaintext_size(&self) -> Option<u64> {
        self.plaintext_size
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn size(&self) -> usize {
        SECURETAR_V3_HEADER_SIZE
    }
}

#[derive(Debug, Clone)]
pub struct SecureTarRootKeyContext {
    password: String,
}

impl SecureTarRootKeyContext {
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
        }
    }

    pub fn restore_key_material(
        &self,
        header: &SecureTarHeader,
    ) -> Result<SecureTarDerivedKeyMaterialV3> {
        if header.version != V3_VERSION {
            return Err(SecureTarError::UnsupportedVersion(header.version));
        }

        let init = SecureTarV3CipherInitialization::parse(header.cipher_initialization())?;
        let root_key = derive_root_key(&self.password, &init.root_salt)?;
        let validation_key = blake2b_key(&root_key, &init.validation_salt);

        if !constant_time_eq(&validation_key, &init.validation_key) {
            return Err(SecureTarError::InvalidPassword);
        }

        let key = blake2b_key(&root_key, &init.derivation_salt);
        let iv = secretstream::Header::from_slice(&init.secretstream_header)
            .ok_or(SecureTarError::InvalidHeader)?;

        Ok(SecureTarDerivedKeyMaterialV3 {
            key,
            iv,
            cipher_initialization: header.cipher_initialization.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SecureTarDerivedKeyMaterialV3 {
    key: [u8; V3_DERIVED_KEY_SIZE],
    iv: secretstream::Header,
    cipher_initialization: Vec<u8>,
}

impl SecureTarDerivedKeyMaterialV3 {
    pub fn key(&self) -> &[u8; V3_DERIVED_KEY_SIZE] {
        &self.key
    }

    pub fn cipher_initialization(&self) -> &[u8] {
        &self.cipher_initialization
    }
}

pub struct SecureTarDecryptStream<R> {
    header: SecureTarHeader,
    reader: DecryptReader<R>,
}

impl<R: Read> SecureTarDecryptStream<R> {
    pub fn new(source: R, root_key_context: SecureTarRootKeyContext) -> Result<Self> {
        Self::with_ciphertext_size(source, root_key_context, None)
    }

    pub fn with_ciphertext_size(
        mut source: R,
        root_key_context: SecureTarRootKeyContext,
        ciphertext_size: Option<u64>,
    ) -> Result<Self> {
        let header = SecureTarHeader::from_reader(&mut source)?;
        Self::from_header_and_source(source, header, root_key_context, ciphertext_size)
    }

    pub fn with_prefix(
        prefix: &[u8],
        mut source: R,
        root_key_context: SecureTarRootKeyContext,
    ) -> Result<Self> {
        let header = SecureTarHeader::from_prefix_and_reader(prefix, &mut source)?;
        Self::from_header_and_source(source, header, root_key_context, None)
    }

    fn from_header_and_source(
        source: R,
        header: SecureTarHeader,
        root_key_context: SecureTarRootKeyContext,
        outer_ciphertext_size: Option<u64>,
    ) -> Result<Self> {
        let key_material = root_key_context.restore_key_material(&header)?;
        let plaintext_size = header
            .plaintext_size()
            .ok_or(SecureTarError::MissingPlaintextSize)?;
        let computed_ciphertext_size = plaintext_size + secretstream_overhead(plaintext_size);
        let ciphertext_size = outer_ciphertext_size
            .map(|size| size.saturating_sub(header.size() as u64))
            .unwrap_or(computed_ciphertext_size);

        let key = secretstream::Key::from_slice(key_material.key())
            .ok_or(SecureTarError::InvalidHeader)?;
        let stream = secretstream::Stream::init_pull(&key_material.iv, &key)
            .map_err(|_| SecureTarError::SecretStreamFailure)?;

        Ok(Self {
            header,
            reader: DecryptReader {
                source,
                stream,
                buffer: Cursor::new(Vec::new()),
                plaintext_size,
                ciphertext_size,
                pos: 0,
                done: false,
            },
        })
    }

    pub fn header(&self) -> &SecureTarHeader {
        &self.header
    }

    pub fn into_reader(self) -> DecryptReader<R> {
        self.reader
    }

    pub fn validate(mut self, basic_validation: bool) -> bool {
        validate_reader(&mut self.reader, basic_validation)
    }
}

impl<R: Read> Read for SecureTarDecryptStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

pub struct DecryptReader<R> {
    source: R,
    stream: secretstream::Stream<secretstream::Pull>,
    buffer: Cursor<Vec<u8>>,
    plaintext_size: u64,
    ciphertext_size: u64,
    pos: u64,
    done: bool,
}

impl<R: Read> DecryptReader<R> {
    pub fn plaintext_size(&self) -> u64 {
        self.plaintext_size
    }

    fn fill_buffer(&mut self, size: usize) -> Result<()> {
        while self.buffer.position() as usize >= self.buffer.get_ref().len() && !self.done {
            let remaining = self.ciphertext_size.saturating_sub(self.pos);
            let chunk_size =
                (V3_SECRETSTREAM_CHUNK_SIZE + V3_SECRETSTREAM_ABYTES as u64).min(remaining);

            if chunk_size == 0 {
                return Err(SecureTarError::CiphertextTooShort);
            }

            let mut encrypted = vec![0; chunk_size as usize];
            let read = self.source.read(&mut encrypted)?;
            encrypted.truncate(read);
            self.pos += read as u64;

            if encrypted.is_empty() {
                return Err(SecureTarError::CiphertextTooShort);
            }

            let (plaintext, tag) = self
                .stream
                .pull(&encrypted, None)
                .map_err(|_| SecureTarError::SecretStreamFailure)?;

            let remaining = self.ciphertext_size.saturating_sub(self.pos);
            if tag == secretstream::Tag::Final && remaining != 0 {
                return Err(SecureTarError::UnexpectedFinalTag);
            }
            if remaining == 0 && tag != secretstream::Tag::Final {
                return Err(SecureTarError::MissingFinalTag);
            }

            self.done = tag == secretstream::Tag::Final;
            self.buffer = Cursor::new(plaintext);

            if self.buffer.get_ref().len() >= size || self.done {
                break;
            }
        }

        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        self.fill_buffer(buf.len()).map_err(std::io::Error::other)?;
        self.buffer.read(buf)
    }
}

pub fn validate_password<R: Read>(source: R, password: impl Into<String>) -> bool {
    validate(source, password, true)
}

pub fn validate<R: Read>(source: R, password: impl Into<String>, basic_validation: bool) -> bool {
    let context = SecureTarRootKeyContext::new(password);
    let Ok(stream) = SecureTarDecryptStream::new(source, context) else {
        return false;
    };

    stream.validate(basic_validation)
}

fn validate_reader(reader: &mut impl Read, basic_validation: bool) -> bool {
    let mut buffer = vec![0; if basic_validation { 1 } else { 1024 * 1024 }];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return true,
            Ok(_) if basic_validation => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

pub fn get_archive_max_ciphertext_size(
    plaintext_size: u64,
    version: u8,
    number_of_inner_tar_files: u64,
) -> Result<u64> {
    match version {
        3 => {
            if number_of_inner_tar_files == 0 {
                return Ok(plaintext_size);
            }

            let secretstream_overhead = secretstream_overhead(plaintext_size);
            let num_records = secretstream_overhead.div_ceil(tar_record_size());
            Ok(plaintext_size + (number_of_inner_tar_files + num_records) * tar_record_size())
        }
        other => Err(SecureTarError::UnsupportedVersion(other)),
    }
}

pub fn secretstream_overhead(plaintext_size: u64) -> u64 {
    plaintext_size.div_ceil(V3_SECRETSTREAM_CHUNK_SIZE).max(1) * V3_SECRETSTREAM_ABYTES as u64
}

pub fn v3_ciphertext_size(plaintext_size: u64) -> u64 {
    plaintext_size + secretstream_overhead(plaintext_size)
}

pub fn is_securetar_magic(prefix: &[u8]) -> bool {
    prefix.starts_with(SECURETAR_MAGIC)
}

fn tar_record_size() -> u64 {
    20 * TAR_BLOCK_SIZE as u64
}

#[derive(Debug, Clone)]
struct SecureTarV3CipherInitialization {
    root_salt: [u8; V3_DERIVED_KEY_SALT_SIZE],
    validation_salt: [u8; V3_DERIVED_KEY_SALT_SIZE],
    validation_key: [u8; V3_DERIVED_KEY_SIZE],
    derivation_salt: [u8; V3_DERIVED_KEY_SALT_SIZE],
    secretstream_header: [u8; V3_CHACHA20_HEADER_SIZE],
}

impl SecureTarV3CipherInitialization {
    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECURETAR_V3_CIPHER_INIT_SIZE {
            return Err(SecureTarError::InvalidHeader);
        }

        Ok(Self {
            root_salt: bytes[0..16]
                .try_into()
                .map_err(|_| SecureTarError::InvalidHeader)?,
            validation_salt: bytes[16..32]
                .try_into()
                .map_err(|_| SecureTarError::InvalidHeader)?,
            validation_key: bytes[32..64]
                .try_into()
                .map_err(|_| SecureTarError::InvalidHeader)?,
            derivation_salt: bytes[64..80]
                .try_into()
                .map_err(|_| SecureTarError::InvalidHeader)?,
            secretstream_header: bytes[80..104]
                .try_into()
                .map_err(|_| SecureTarError::InvalidHeader)?,
        })
    }
}

fn derive_root_key(
    password: &str,
    root_salt: &[u8; V3_DERIVED_KEY_SALT_SIZE],
) -> Result<[u8; V3_DERIVED_KEY_SIZE]> {
    sodiumoxide::init().map_err(|_| SecureTarError::SodiumInit)?;

    let params = Params::new(
        V3_KDF_MEMLIMIT / 1024,
        V3_KDF_OPSLIMIT,
        1,
        Some(V3_DERIVED_KEY_SIZE),
    )
    .map_err(|error| SecureTarError::KeyDerivation(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut root_key = [0; V3_DERIVED_KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), root_salt, &mut root_key)
        .map_err(|error| SecureTarError::KeyDerivation(error.to_string()))?;
    Ok(root_key)
}

fn blake2b_key(
    root_key: &[u8; V3_DERIVED_KEY_SIZE],
    salt: &[u8; V3_DERIVED_KEY_SALT_SIZE],
) -> [u8; V3_DERIVED_KEY_SIZE] {
    let hash = blake2b_simd::Params::new()
        .hash_length(V3_DERIVED_KEY_SIZE)
        .key(root_key)
        .salt(salt)
        .personal(V3_PERSONALIZATION)
        .hash(&[]);

    hash.as_bytes().try_into().expect("BLAKE2b output length")
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.iter()
        .zip(right.iter())
        .fold(0, |acc, (left, right)| acc | (left ^ right))
        == 0
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, path::PathBuf};

    use super::*;

    const PASSWORD: &str = "hunter2";

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn archive_max_ciphertext_size_matches_upstream_v3_cases() {
        let cases = [
            (0, 0, 0),
            (10240, 0, 10240),
            (10240, 1, 30720),
            (100000, 3, 140960),
            (1048576, 1, 1069056),
            (1048577, 1, 1069057),
            (5242880, 5, 5304320),
            (10485760, 1, 10506240),
            (1000, 10, 113640),
        ];

        for (plaintext_size, inner_files, expected) in cases {
            assert_eq!(
                get_archive_max_ciphertext_size(plaintext_size, 3, inner_files).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn parses_v3_header_from_fixture() {
        let mut file = File::open(fixture("core_no_final_tag.tar.gz")).unwrap();
        let header = SecureTarHeader::from_reader(&mut file).unwrap();

        assert_eq!(header.version(), 3);
        assert_eq!(header.size(), SECURETAR_V3_HEADER_SIZE);
        assert_eq!(header.cipher_initialization().len(), 104);
        assert_eq!(header.to_bytes().unwrap().len(), SECURETAR_V3_HEADER_SIZE);
    }

    #[test]
    fn wrong_password_does_not_validate() {
        let file = File::open(fixture("core_no_final_tag.tar.gz")).unwrap();

        assert!(!validate_password(file, "wrong_password"));
    }

    #[test]
    fn basic_validation_matches_upstream_for_no_final_tag_fixture() {
        let file = File::open(fixture("core_no_final_tag.tar.gz")).unwrap();
        assert!(validate_password(file, PASSWORD));

        let file = File::open(fixture("core_no_final_tag.tar.gz")).unwrap();
        assert!(!validate(file, PASSWORD, false));
    }

    #[test]
    fn early_final_tag_fails_basic_validation() {
        let file = File::open(fixture("core_early_final_tag.tar.gz")).unwrap();
        assert!(!validate_password(file, PASSWORD));
    }

    #[test]
    fn empty_ciphertext_fails_validation() {
        let file = File::open(fixture("core_empty.tar.gz")).unwrap();
        assert!(!validate_password(file, PASSWORD));
    }

    #[test]
    fn exposes_plaintext_size() {
        let file = File::open(fixture("core_no_final_tag.tar.gz")).unwrap();
        let stream =
            SecureTarDecryptStream::new(file, SecureTarRootKeyContext::new(PASSWORD)).unwrap();

        assert_eq!(stream.header().plaintext_size(), Some(3_147_544));
        assert_eq!(stream.into_reader().plaintext_size(), 3_147_544);
    }

    #[test]
    fn prefix_constructor_accepts_partially_consumed_header() {
        let mut file = File::open(fixture("core_no_final_tag.tar.gz")).unwrap();
        let mut prefix = [0; SECURETAR_MAGIC.len()];
        file.read_exact(&mut prefix).unwrap();

        let stream = SecureTarDecryptStream::with_prefix(
            &prefix,
            file,
            SecureTarRootKeyContext::new(PASSWORD),
        )
        .unwrap();

        assert_eq!(stream.header().version(), 3);
    }

    #[test]
    fn v3_ciphertext_size_matches_headerless_payload_size() {
        let plaintext_size = 3_147_544;

        assert_eq!(
            v3_ciphertext_size(plaintext_size),
            3_147_544 + 4 * V3_SECRETSTREAM_ABYTES as u64
        );
    }

    #[test]
    fn read_reports_missing_final_tag() {
        let file = File::open(fixture("core_no_final_tag.tar.gz")).unwrap();
        let mut stream =
            SecureTarDecryptStream::new(file, SecureTarRootKeyContext::new(PASSWORD)).unwrap();
        let mut bytes = Vec::new();
        let error = stream.read_to_end(&mut bytes).unwrap_err();

        assert!(error.to_string().contains("Missing final tag"));
    }
}
