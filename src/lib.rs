#![warn(missing_docs)]

//! SecureTar v3 reader primitives.
//!
//! This crate is an independent Rust implementation aligned with the Python
//! [`home-assistant-libs/securetar`](https://github.com/home-assistant-libs/securetar)
//! package. It currently implements the SecureTar v3 read path: header parsing,
//! password validation, key restoration, and streaming decryption.
//!
//! Legacy SecureTar v1/v2 AES-CBC and archive-writing helpers are intentionally
//! not implemented yet.
//!
//! ```rust,no_run
//! use std::{fs::File, io::Read};
//! use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};
//!
//! let file = File::open("encrypted.securetar")?;
//! let context = SecureTarRootKeyContext::new("password");
//! let mut stream = SecureTarDecryptStream::new(file, context)?;
//!
//! let mut plaintext_tar = Vec::new();
//! stream.read_to_end(&mut plaintext_tar)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::io::{Cursor, Read};

use argon2::{Algorithm, Argon2, Params, Version};
use log::{debug, error, trace};
use sodiumoxide::crypto::secretstream::xchacha20poly1305 as secretstream;
use thiserror::Error;

/// AES block size used by legacy SecureTar v1/v2.
pub const AES_BLOCK_SIZE: usize = 16;
/// AES IV size used by legacy SecureTar v1/v2.
pub const AES_IV_SIZE: usize = AES_BLOCK_SIZE;

/// Secretstream authentication bytes per v3 chunk.
pub const V3_SECRETSTREAM_ABYTES: usize = 17;
/// Plaintext bytes per v3 secretstream chunk.
pub const V3_SECRETSTREAM_CHUNK_SIZE: u64 = 1024 * 1024;
/// Argon2id operation limit for v3 keys.
pub const V3_KDF_OPSLIMIT: u32 = 8;
/// Argon2id memory limit, in bytes, for v3 keys.
pub const V3_KDF_MEMLIMIT: u32 = 16 * 1024 * 1024;
/// Size of v3 derived keys.
pub const V3_DERIVED_KEY_SIZE: usize = 32;
/// Size of v3 BLAKE2b salts.
pub const V3_DERIVED_KEY_SALT_SIZE: usize = 16;
/// Size of the XChaCha20-Poly1305 secretstream header.
pub const V3_CHACHA20_HEADER_SIZE: usize = 24;

/// Default Python securetar buffer size.
pub const DEFAULT_BUFSIZE: usize = 10240;

/// SecureTar magic bytes.
pub const SECURETAR_MAGIC: &[u8] = b"SecureTar";
/// Required reserved bytes in the SecureTar file id.
pub const SECURETAR_MAGIC_RESERVED: [u8; 6] = [0; 6];

/// Header size for legacy magic-less SecureTar v1.
pub const SECURETAR_LEGACY_HEADER_SIZE: usize = AES_IV_SIZE;
/// Size of the SecureTar file id section.
pub const SECURETAR_FILE_ID_SIZE: usize = 16;
/// Size of the SecureTar metadata section.
pub const SECURETAR_FILE_METADATA_SIZE: usize = 16;
/// Size of the v2 cipher initialization section.
pub const SECURETAR_V2_CIPHER_INIT_SIZE: usize = AES_IV_SIZE;
/// Size of a v2 header.
pub const SECURETAR_V2_HEADER_SIZE: usize =
    SECURETAR_FILE_ID_SIZE + SECURETAR_FILE_METADATA_SIZE + SECURETAR_V2_CIPHER_INIT_SIZE;
/// Size of the v3 cipher initialization section.
pub const SECURETAR_V3_CIPHER_INIT_SIZE: usize = 104;
/// Size of a v3 header.
pub const SECURETAR_V3_HEADER_SIZE: usize =
    SECURETAR_FILE_ID_SIZE + SECURETAR_FILE_METADATA_SIZE + SECURETAR_V3_CIPHER_INIT_SIZE;

/// Gzip magic bytes used by Python validation.
pub const GZIP_MAGIC_BYTES: &[u8] = b"\x1f\x8b\x08";
/// Tar magic bytes used by Python validation.
pub const TAR_MAGIC_BYTES: &[u8] = b"ustar";
/// Tar magic offset used by Python validation.
pub const TAR_MAGIC_OFFSET: usize = 257;
/// Tar block size.
pub const TAR_BLOCK_SIZE: usize = 512;

/// Default SecureTar version for new encrypted data in Python.
pub const DEFAULT_CIPHER_VERSION: u8 = 3;

const V3_VERSION: u8 = 3;
const V3_PERSONALIZATION: &[u8; 11] = b"SecureTarv3";

/// SecureTar errors.
#[derive(Debug, Error)]
pub enum SecureTarError {
    /// The stream version is not implemented by this crate.
    #[error("Unsupported SecureTar version: {0}")]
    UnsupportedVersion(u8),

    /// Reserved header bytes were not zero.
    #[error("Invalid reserved bytes in SecureTar header")]
    InvalidReservedBytes,

    /// A v3 operation needed a plaintext size.
    #[error("Plaintext size is required")]
    MissingPlaintextSize,

    /// Header bytes were malformed.
    #[error("Invalid SecureTar header")]
    InvalidHeader,

    /// Password validation failed.
    #[error("Invalid password")]
    InvalidPassword,

    /// A final secretstream tag arrived before expected ciphertext end.
    #[error("Unexpected final tag in secretstream decryption")]
    UnexpectedFinalTag,

    /// Ciphertext ended without a final secretstream tag.
    #[error("Missing final tag in secretstream decryption")]
    MissingFinalTag,

    /// Ciphertext was shorter than required.
    #[error("Ciphertext is too short")]
    CiphertextTooShort,

    /// Secretstream decryption failed.
    #[error("Unexpected failure")]
    SecretStreamFailure,

    /// Sodium initialization failed.
    #[error("failed to initialize sodiumoxide")]
    SodiumInit,

    /// Argon2id key derivation failed.
    #[error("failed to derive SecureTar v3 root key: {0}")]
    KeyDerivation(String),

    /// I/O failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Crate result type.
pub type Result<T> = std::result::Result<T, SecureTarError>;

/// Cipher direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// Encrypt mode.
    Encrypt,
    /// Decrypt mode.
    Decrypt,
}

/// Parsed SecureTar header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureTarHeader {
    cipher_initialization: Vec<u8>,
    plaintext_size: Option<u64>,
    version: u8,
}

impl SecureTarHeader {
    /// Builds a v3 header from raw cipher initialization bytes.
    ///
    /// ```
    /// # use securetar::{SecureTarHeader, SECURETAR_V3_CIPHER_INIT_SIZE};
    /// let header = SecureTarHeader::new(vec![0; SECURETAR_V3_CIPHER_INIT_SIZE], Some(0), 3)?;
    /// assert_eq!(header.version(), 3);
    /// # Ok::<(), securetar::SecureTarError>(())
    /// ```
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

    /// Reads a header from the front of a stream.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::SecureTarHeader;
    /// let mut file = File::open("encrypted.securetar")?;
    /// let header = SecureTarHeader::from_reader(&mut file)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_reader(reader: &mut impl Read) -> Result<Self> {
        let mut file_id = [0; SECURETAR_FILE_ID_SIZE];
        reader.read_exact(&mut file_id)?;
        Self::from_file_id_and_reader(file_id, reader)
    }

    /// Reads a header after the caller already consumed a prefix.
    ///
    /// ```rust,no_run
    /// # use std::{fs::File, io::Read};
    /// # use securetar::{SecureTarHeader, SECURETAR_MAGIC};
    /// let mut file = File::open("encrypted.securetar")?;
    /// let mut prefix = [0; SECURETAR_MAGIC.len()];
    /// file.read_exact(&mut prefix)?;
    /// let header = SecureTarHeader::from_prefix_and_reader(&prefix, &mut file)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
            debug!("securetar header magic did not match; treating stream as legacy v1");
            return Err(SecureTarError::UnsupportedVersion(1));
        }

        let version = file_id[SECURETAR_MAGIC.len()];
        if version != V3_VERSION {
            debug!("unsupported securetar version in header: {version}");
            return Err(SecureTarError::UnsupportedVersion(version));
        }
        if file_id[10..16] != SECURETAR_MAGIC_RESERVED {
            debug!("securetar header reserved bytes were non-zero");
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

        debug!("parsed securetar header: version={version} plaintext_size={plaintext_size}");

        Ok(Self {
            cipher_initialization,
            plaintext_size: Some(plaintext_size),
            version,
        })
    }

    /// Serializes this header.
    ///
    /// ```
    /// # use securetar::{SecureTarHeader, SECURETAR_V3_CIPHER_INIT_SIZE, SECURETAR_V3_HEADER_SIZE};
    /// let header = SecureTarHeader::new(vec![0; SECURETAR_V3_CIPHER_INIT_SIZE], Some(0), 3)?;
    /// assert_eq!(header.to_bytes()?.len(), SECURETAR_V3_HEADER_SIZE);
    /// # Ok::<(), securetar::SecureTarError>(())
    /// ```
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

    /// Returns raw cipher initialization bytes.
    ///
    /// ```
    /// # use securetar::{SecureTarHeader, SECURETAR_V3_CIPHER_INIT_SIZE};
    /// let header = SecureTarHeader::new(vec![0; SECURETAR_V3_CIPHER_INIT_SIZE], Some(0), 3)?;
    /// assert_eq!(header.cipher_initialization().len(), SECURETAR_V3_CIPHER_INIT_SIZE);
    /// # Ok::<(), securetar::SecureTarError>(())
    /// ```
    pub fn cipher_initialization(&self) -> &[u8] {
        &self.cipher_initialization
    }

    /// Returns plaintext size from the header.
    ///
    /// ```
    /// # use securetar::{SecureTarHeader, SECURETAR_V3_CIPHER_INIT_SIZE};
    /// let header = SecureTarHeader::new(vec![0; SECURETAR_V3_CIPHER_INIT_SIZE], Some(42), 3)?;
    /// assert_eq!(header.plaintext_size(), Some(42));
    /// # Ok::<(), securetar::SecureTarError>(())
    /// ```
    pub fn plaintext_size(&self) -> Option<u64> {
        self.plaintext_size
    }

    /// Returns the SecureTar version.
    ///
    /// ```
    /// # use securetar::{SecureTarHeader, SECURETAR_V3_CIPHER_INIT_SIZE};
    /// let header = SecureTarHeader::new(vec![0; SECURETAR_V3_CIPHER_INIT_SIZE], Some(0), 3)?;
    /// assert_eq!(header.version(), 3);
    /// # Ok::<(), securetar::SecureTarError>(())
    /// ```
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns header size in bytes.
    ///
    /// ```
    /// # use securetar::{SecureTarHeader, SECURETAR_V3_CIPHER_INIT_SIZE, SECURETAR_V3_HEADER_SIZE};
    /// let header = SecureTarHeader::new(vec![0; SECURETAR_V3_CIPHER_INIT_SIZE], Some(0), 3)?;
    /// assert_eq!(header.size(), SECURETAR_V3_HEADER_SIZE);
    /// # Ok::<(), securetar::SecureTarError>(())
    /// ```
    pub fn size(&self) -> usize {
        SECURETAR_V3_HEADER_SIZE
    }
}

/// Password context for restoring per-file v3 key material.
#[derive(Debug, Clone)]
pub struct SecureTarRootKeyContext {
    password: String,
}

impl SecureTarRootKeyContext {
    /// Creates a password context.
    ///
    /// ```
    /// # use securetar::SecureTarRootKeyContext;
    /// let context = SecureTarRootKeyContext::new("password");
    /// ```
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
        }
    }

    /// Restores v3 key material from a parsed header.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarHeader, SecureTarRootKeyContext};
    /// let mut file = File::open("encrypted.securetar")?;
    /// let header = SecureTarHeader::from_reader(&mut file)?;
    /// let key = SecureTarRootKeyContext::new("password").restore_key_material(&header)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
            debug!("securetar validation key did not match");
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

/// Restored v3 key material.
#[derive(Debug, Clone)]
pub struct SecureTarDerivedKeyMaterialV3 {
    key: [u8; V3_DERIVED_KEY_SIZE],
    iv: secretstream::Header,
    cipher_initialization: Vec<u8>,
}

impl SecureTarDerivedKeyMaterialV3 {
    /// Returns the derived encryption key.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarHeader, SecureTarRootKeyContext};
    /// let mut file = File::open("encrypted.securetar")?;
    /// let header = SecureTarHeader::from_reader(&mut file)?;
    /// let key = SecureTarRootKeyContext::new("password").restore_key_material(&header)?;
    /// assert_eq!(key.key().len(), 32);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn key(&self) -> &[u8; V3_DERIVED_KEY_SIZE] {
        &self.key
    }

    /// Returns header cipher initialization bytes.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarHeader, SecureTarRootKeyContext};
    /// let mut file = File::open("encrypted.securetar")?;
    /// let header = SecureTarHeader::from_reader(&mut file)?;
    /// let key = SecureTarRootKeyContext::new("password").restore_key_material(&header)?;
    /// assert!(!key.cipher_initialization().is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn cipher_initialization(&self) -> &[u8] {
        &self.cipher_initialization
    }
}

/// Decrypting SecureTar v3 stream.
pub struct SecureTarDecryptStream<R> {
    header: SecureTarHeader,
    reader: DecryptReader<R>,
}

impl<R: Read> SecureTarDecryptStream<R> {
    /// Opens a decrypting stream from encrypted input.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};
    /// let file = File::open("encrypted.securetar")?;
    /// let stream = SecureTarDecryptStream::new(file, SecureTarRootKeyContext::new("password"))?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(source: R, root_key_context: SecureTarRootKeyContext) -> Result<Self> {
        Self::with_ciphertext_size(source, root_key_context, None)
    }

    /// Opens a stream with known total ciphertext size.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};
    /// let file = File::open("encrypted.securetar")?;
    /// let size = file.metadata()?.len();
    /// let stream = SecureTarDecryptStream::with_ciphertext_size(
    ///     file,
    ///     SecureTarRootKeyContext::new("password"),
    ///     Some(size),
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_ciphertext_size(
        mut source: R,
        root_key_context: SecureTarRootKeyContext,
        ciphertext_size: Option<u64>,
    ) -> Result<Self> {
        let header = SecureTarHeader::from_reader(&mut source)?;
        Self::from_header_and_source(source, header, root_key_context, ciphertext_size)
    }

    /// Opens a stream after the caller consumed a prefix.
    ///
    /// ```rust,no_run
    /// # use std::{fs::File, io::Read};
    /// # use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext, SECURETAR_MAGIC};
    /// let mut file = File::open("encrypted.securetar")?;
    /// let mut prefix = [0; SECURETAR_MAGIC.len()];
    /// file.read_exact(&mut prefix)?;
    /// let stream = SecureTarDecryptStream::with_prefix(
    ///     &prefix,
    ///     file,
    ///     SecureTarRootKeyContext::new("password"),
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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

        debug!(
            "opening securetar decrypt stream: plaintext_size={plaintext_size} computed_ciphertext_size={computed_ciphertext_size} outer_ciphertext_size={outer_ciphertext_size:?} ciphertext_size={ciphertext_size}"
        );

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

    /// Returns the parsed header.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};
    /// let file = File::open("encrypted.securetar")?;
    /// let stream = SecureTarDecryptStream::new(file, SecureTarRootKeyContext::new("password"))?;
    /// assert_eq!(stream.header().version(), 3);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn header(&self) -> &SecureTarHeader {
        &self.header
    }

    /// Returns the inner plaintext reader.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};
    /// let file = File::open("encrypted.securetar")?;
    /// let reader = SecureTarDecryptStream::new(file, SecureTarRootKeyContext::new("password"))?
    ///     .into_reader();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn into_reader(self) -> DecryptReader<R> {
        self.reader
    }

    /// Validates password or full stream integrity.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};
    /// let file = File::open("encrypted.securetar")?;
    /// let ok = SecureTarDecryptStream::new(file, SecureTarRootKeyContext::new("password"))?
    ///     .validate(true);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn validate(mut self, basic_validation: bool) -> bool {
        validate_reader(&mut self.reader, basic_validation)
    }
}

impl<R: Read> Read for SecureTarDecryptStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

/// Plaintext reader returned by [`SecureTarDecryptStream`].
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
    /// Returns expected plaintext size.
    ///
    /// ```rust,no_run
    /// # use std::fs::File;
    /// # use securetar::{SecureTarDecryptStream, SecureTarRootKeyContext};
    /// let file = File::open("encrypted.securetar")?;
    /// let reader = SecureTarDecryptStream::new(file, SecureTarRootKeyContext::new("password"))?
    ///     .into_reader();
    /// let size = reader.plaintext_size();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn plaintext_size(&self) -> u64 {
        self.plaintext_size
    }

    fn fill_buffer(&mut self, size: usize) -> Result<()> {
        while self.buffer.position() as usize >= self.buffer.get_ref().len() && !self.done {
            let remaining = self.ciphertext_size.saturating_sub(self.pos);
            let chunk_size =
                (V3_SECRETSTREAM_CHUNK_SIZE + V3_SECRETSTREAM_ABYTES as u64).min(remaining);

            trace!(
                "reading securetar ciphertext chunk: requested_plaintext={size} ciphertext_pos={} ciphertext_size={} remaining={remaining} chunk_size={chunk_size}",
                self.pos, self.ciphertext_size
            );

            if chunk_size == 0 {
                debug!(
                    "securetar ciphertext ended before final tag: ciphertext_pos={} ciphertext_size={}",
                    self.pos, self.ciphertext_size
                );
                return Err(SecureTarError::CiphertextTooShort);
            }

            let mut encrypted = vec![0; chunk_size as usize];
            self.source.read_exact(&mut encrypted)?;
            let read = encrypted.len();
            self.pos += read as u64;

            trace!(
                "read securetar ciphertext bytes: read={read} ciphertext_pos={}",
                self.pos
            );

            if encrypted.is_empty() {
                debug!(
                    "securetar source returned EOF before final tag: ciphertext_pos={} ciphertext_size={}",
                    self.pos, self.ciphertext_size
                );
                return Err(SecureTarError::CiphertextTooShort);
            }

            let (plaintext, tag) = self.stream.pull(&encrypted, None).map_err(|_| {
                    error!(
                        "securetar secretstream pull failed: encrypted_len={} ciphertext_pos={} ciphertext_size={}",
                        encrypted.len(), self.pos, self.ciphertext_size
                    );
                SecureTarError::SecretStreamFailure
            })?;

            let remaining = self.ciphertext_size.saturating_sub(self.pos);
            if tag == secretstream::Tag::Final && remaining != 0 {
                debug!(
                    "securetar final tag arrived before expected ciphertext end: ciphertext_pos={} ciphertext_size={} remaining={remaining}",
                    self.pos, self.ciphertext_size
                );
                return Err(SecureTarError::UnexpectedFinalTag);
            }
            if remaining == 0 && tag != secretstream::Tag::Final {
                debug!(
                    "securetar ciphertext ended without final tag: ciphertext_pos={} ciphertext_size={}",
                    self.pos, self.ciphertext_size
                );
                return Err(SecureTarError::MissingFinalTag);
            }

            self.done = tag == secretstream::Tag::Final;
            self.buffer = Cursor::new(plaintext);

            trace!(
                "decrypted securetar plaintext chunk: plaintext_len={} final_tag={} remaining={remaining}",
                self.buffer.get_ref().len(),
                self.done
            );

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

/// Validates that a password can decrypt the beginning of the stream.
///
/// ```rust,no_run
/// # use std::fs::File;
/// # use securetar::validate_password;
/// let file = File::open("encrypted.securetar")?;
/// let ok = validate_password(file, "password");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn validate_password<R: Read>(source: R, password: impl Into<String>) -> bool {
    validate(source, password, true)
}

/// Validates a stream; pass `false` to read through the final tag.
///
/// ```rust,no_run
/// # use std::fs::File;
/// # use securetar::validate;
/// let file = File::open("encrypted.securetar")?;
/// let ok = validate(file, "password", false);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
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

/// Returns Python-compatible maximum outer archive ciphertext size.
///
/// ```
/// # use securetar::get_archive_max_ciphertext_size;
/// assert_eq!(get_archive_max_ciphertext_size(10240, 3, 1)?, 30720);
/// # Ok::<(), securetar::SecureTarError>(())
/// ```
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

/// Returns v3 secretstream overhead for a plaintext size.
///
/// ```
/// # use securetar::secretstream_overhead;
/// assert_eq!(secretstream_overhead(0), 17);
/// ```
pub fn secretstream_overhead(plaintext_size: u64) -> u64 {
    plaintext_size.div_ceil(V3_SECRETSTREAM_CHUNK_SIZE).max(1) * V3_SECRETSTREAM_ABYTES as u64
}

/// Returns v3 payload ciphertext size, excluding the header.
///
/// ```
/// # use securetar::v3_ciphertext_size;
/// assert_eq!(v3_ciphertext_size(0), 17);
/// ```
pub fn v3_ciphertext_size(plaintext_size: u64) -> u64 {
    plaintext_size + secretstream_overhead(plaintext_size)
}

/// Checks whether bytes start with SecureTar magic.
///
/// ```
/// # use securetar::{is_securetar_magic, SECURETAR_MAGIC};
/// assert!(is_securetar_magic(SECURETAR_MAGIC));
/// ```
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
