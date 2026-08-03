use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bip39::{Language, Mnemonic};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub const ENVELOPE_VERSION: u16 = 1;
pub const ALGORITHM: &str = "xchacha20-poly1305";
pub const SYNC_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
const AAD_PREFIX: &[u8] = b"kclip-sync-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RevisionV1 {
    pub revision_id: String,
    pub slot: String,
    pub origin_device_id: String,
    pub origin_sequence: u64,
    pub hlc_physical: i64,
    pub hlc_logical: u32,
    pub content_hash: Option<String>,
    pub content_size: u64,
    pub content_type: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub is_deleted: bool,
    pub source_adapter: String,
    pub parent_revision_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncEnvelopeV1 {
    pub envelope_version: u16,
    pub message_id: String,
    pub revision: RevisionV1,
    pub content: Option<ByteBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedEnvelope {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
}

impl SyncEnvelopeV1 {
    pub fn new(message_id: String, revision: RevisionV1, content: Option<Vec<u8>>) -> Self {
        Self {
            envelope_version: ENVELOPE_VERSION,
            message_id,
            revision,
            content: content.map(ByteBuf::from),
        }
    }

    pub fn validate(&self, outer_message_id: &str, maximum_size: u64) -> Result<(), CryptoError> {
        if self.envelope_version != ENVELOPE_VERSION {
            return Err(CryptoError::InvalidEnvelope("unsupported envelope version"));
        }
        if self.message_id != outer_message_id {
            return Err(CryptoError::InvalidEnvelope(
                "inner and outer message IDs differ",
            ));
        }
        kclip_protocol::validate_slot_name(&self.revision.slot)
            .map_err(|_| CryptoError::InvalidEnvelope("invalid slot name"))?;
        if self.revision.origin_device_id.is_empty()
            || self.revision.origin_device_id.len() > 128
            || self.revision.origin_sequence == 0
            || self.revision.revision_id.len() > 256
            || self.revision.source_adapter.is_empty()
            || self.revision.source_adapter.len() > 64
            || self
                .revision
                .content_type
                .as_ref()
                .is_some_and(|value| value.len() > 1_024)
            || self
                .revision
                .parent_revision_id
                .as_ref()
                .is_some_and(|value| value.len() > 256)
        {
            return Err(CryptoError::InvalidEnvelope(
                "revision metadata exceeds field limits",
            ));
        }
        if self.revision.revision_id
            != format!(
                "{}:{}",
                self.revision.origin_device_id, self.revision.origin_sequence
            )
        {
            return Err(CryptoError::InvalidEnvelope("invalid revision identity"));
        }
        if self.revision.content_size > maximum_size {
            return Err(CryptoError::ContentTooLarge {
                actual: self.revision.content_size,
                maximum: maximum_size,
            });
        }
        if self.revision.is_deleted {
            if self.content.is_some()
                || self.revision.content_hash.is_some()
                || self.revision.content_size != 0
            {
                return Err(CryptoError::InvalidEnvelope("invalid tombstone content"));
            }
        } else {
            let content = self
                .content
                .as_deref()
                .ok_or(CryptoError::InvalidEnvelope("live revision has no content"))?;
            if content.len() as u64 != self.revision.content_size {
                return Err(CryptoError::InvalidEnvelope("content size does not match"));
            }
            let expected =
                self.revision
                    .content_hash
                    .as_deref()
                    .ok_or(CryptoError::InvalidEnvelope(
                        "live revision has no content hash",
                    ))?;
            if expected.len() != 64
                || expected
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            {
                return Err(CryptoError::InvalidEnvelope("invalid SHA-256 content hash"));
            }
            if sha256_hex(content) != expected {
                return Err(CryptoError::InvalidEnvelope("content hash does not match"));
            }
        }
        Ok(())
    }
}

pub fn canonical_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, CryptoError> {
    // serde_cbor::Value maps use RFC 7049 canonical ordering. Converting through
    // Value also prevents Rust declaration order from becoming wire contract.
    let value = serde_cbor::value::to_value(value)?;
    Ok(serde_cbor::to_vec(&value)?)
}

pub fn decode_canonical<T>(bytes: &[u8]) -> Result<T, CryptoError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_cbor::from_slice(bytes)?;
    if canonical_cbor(&value)? != bytes {
        return Err(CryptoError::NonCanonicalCbor);
    }
    Ok(value)
}

pub fn encrypt(
    key: &[u8; SYNC_KEY_SIZE],
    envelope: &SyncEnvelopeV1,
) -> Result<EncryptedEnvelope, CryptoError> {
    let mut nonce = [0_u8; NONCE_SIZE];
    getrandom::fill(&mut nonce).map_err(|_| CryptoError::Randomness)?;
    encrypt_with_nonce(key, envelope, nonce)
}

pub fn encrypt_with_nonce(
    key: &[u8; SYNC_KEY_SIZE],
    envelope: &SyncEnvelopeV1,
    nonce: [u8; NONCE_SIZE],
) -> Result<EncryptedEnvelope, CryptoError> {
    let mut ciphertext = canonical_cbor(envelope)?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            aad(&envelope.message_id).as_slice(),
            &mut ciphertext,
        )
        .map_err(|_| CryptoError::Encryption)?;
    Ok(EncryptedEnvelope {
        algorithm: ALGORITHM.into(),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        tag: URL_SAFE_NO_PAD.encode(tag),
    })
}

pub fn decrypt(
    key: &[u8; SYNC_KEY_SIZE],
    message_id: &str,
    encrypted: &EncryptedEnvelope,
) -> Result<SyncEnvelopeV1, CryptoError> {
    if encrypted.algorithm != ALGORITHM {
        return Err(CryptoError::UnsupportedAlgorithm);
    }
    let nonce = decode_exact::<NONCE_SIZE>(&encrypted.nonce, "nonce")?;
    let tag = decode_exact::<TAG_SIZE>(&encrypted.tag, "tag")?;
    let mut plaintext = URL_SAFE_NO_PAD
        .decode(&encrypted.ciphertext)
        .map_err(|_| CryptoError::InvalidEncoding("ciphertext"))?;
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            aad(message_id).as_slice(),
            &mut plaintext,
            (&tag).into(),
        )
        .map_err(|_| CryptoError::Authentication)?;
    let envelope = decode_canonical::<SyncEnvelopeV1>(&plaintext)?;
    if envelope.message_id != message_id {
        return Err(CryptoError::InvalidEnvelope(
            "inner and outer message IDs differ",
        ));
    }
    Ok(envelope)
}

fn decode_exact<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], CryptoError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEncoding(field))?;
    bytes
        .try_into()
        .map_err(|_| CryptoError::InvalidEncoding(field))
}

fn aad(message_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + message_id.len());
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(message_id.as_bytes());
    aad
}

pub fn sha256_hex(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

pub fn read_sync_key(path: &Path) -> Result<[u8; SYNC_KEY_SIZE], CryptoError> {
    validate_secret_file(path)?;
    let bytes = fs::read(path).map_err(|source| CryptoError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    bytes.try_into().map_err(|_| CryptoError::InvalidKeyLength)
}

pub fn write_sync_key(path: &Path, key: &[u8; SYNC_KEY_SIZE]) -> Result<(), CryptoError> {
    atomic_write_secret(path, key)
}

pub fn generate_sync_key(path: &Path) -> Result<[u8; SYNC_KEY_SIZE], CryptoError> {
    let mut key = [0_u8; SYNC_KEY_SIZE];
    getrandom::fill(&mut key).map_err(|_| CryptoError::Randomness)?;
    write_sync_key(path, &key)?;
    Ok(key)
}

pub fn mnemonic_for_key(key: &[u8; SYNC_KEY_SIZE]) -> Result<String, CryptoError> {
    Ok(Mnemonic::from_entropy(key)
        .map_err(|_| CryptoError::InvalidMnemonic)?
        .to_string())
}

pub fn key_from_mnemonic(words: &str) -> Result<[u8; SYNC_KEY_SIZE], CryptoError> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, words)
        .map_err(|_| CryptoError::InvalidMnemonic)?;
    mnemonic
        .to_entropy()
        .try_into()
        .map_err(|_| CryptoError::InvalidMnemonic)
}

pub fn import_legacy_key(source: &Path, destination: &Path) -> Result<(), CryptoError> {
    let key = read_sync_key(source)?;
    write_sync_key(destination, &key)
}

pub fn validate_secret_file(path: &Path) -> Result<(), CryptoError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| CryptoError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(CryptoError::UnsafeSecret(path.to_path_buf()));
    }
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(CryptoError::UnsafePermissions(path.to_path_buf()));
    }
    Ok(())
}

pub fn atomic_write_secret(path: &Path, bytes: &[u8]) -> Result<(), CryptoError> {
    let parent = path
        .parent()
        .ok_or_else(|| CryptoError::UnsafeSecret(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| CryptoError::Write {
        path: parent.to_path_buf(),
        source,
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|source| CryptoError::Read {
        path: parent.to_path_buf(),
        source,
    })?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(CryptoError::UnsafeSecret(parent.to_path_buf()));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CryptoError::UnsafeSecret(path.to_path_buf()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(CryptoError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
        CryptoError::Write {
            path: parent.to_path_buf(),
            source,
        }
    })?;

    let file_name = path
        .file_name()
        .ok_or_else(|| CryptoError::UnsafeSecret(path.to_path_buf()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = parent.join(format!(
        ".{}.{}.{nonce}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|source| CryptoError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid encrypted {0} encoding")]
    InvalidEncoding(&'static str),
    #[error("unsupported synchronization algorithm")]
    UnsupportedAlgorithm,
    #[error("could not obtain secure randomness")]
    Randomness,
    #[error("encryption failed")]
    Encryption,
    #[error("ciphertext authentication failed")]
    Authentication,
    #[error("invalid synchronization envelope: {0}")]
    InvalidEnvelope(&'static str),
    #[error("decoded content is {actual} bytes; maximum is {maximum}")]
    ContentTooLarge { actual: u64, maximum: u64 },
    #[error("CBOR is not in canonical form")]
    NonCanonicalCbor,
    #[error("invalid 32-byte synchronization key")]
    InvalidKeyLength,
    #[error("invalid 24-word BIP-39 mnemonic")]
    InvalidMnemonic,
    #[error("secret path is not a regular non-symbolic-link file: {0}")]
    UnsafeSecret(PathBuf),
    #[error("secret must be owned by this user and inaccessible to group and other: {0}")]
    UnsafePermissions(PathBuf),
    #[error("could not read secret at {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("could not write secret at {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("CBOR error: {0}")]
    Cbor(#[from] serde_cbor::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn revision() -> RevisionV1 {
        let content = b"hello";
        RevisionV1 {
            revision_id: "device-a:7".into(),
            slot: "default".into(),
            origin_device_id: "device-a".into(),
            origin_sequence: 7,
            hlc_physical: 100,
            hlc_logical: 2,
            content_hash: Some(sha256_hex(content)),
            content_size: content.len() as u64,
            content_type: Some("text/plain; charset=utf-8".into()),
            created_at: 100,
            expires_at: None,
            is_deleted: false,
            source_adapter: "cli".into(),
            parent_revision_id: None,
        }
    }

    #[test]
    fn deterministic_encryption_vector_and_authenticated_message_id() {
        let key = [7_u8; SYNC_KEY_SIZE];
        let envelope = SyncEnvelopeV1::new("message-1".into(), revision(), Some(b"hello".to_vec()));
        let encrypted = encrypt_with_nonce(&key, &envelope, [9_u8; NONCE_SIZE]).unwrap();
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/sync-v1.json")).unwrap();
        assert_eq!(
            URL_SAFE_NO_PAD.encode(canonical_cbor(&envelope).unwrap()),
            fixture["canonical_cbor_base64url"].as_str().unwrap()
        );
        assert_eq!(encrypted.nonce, fixture["nonce"].as_str().unwrap());
        assert_eq!(
            encrypted.ciphertext,
            fixture["ciphertext"].as_str().unwrap()
        );
        assert_eq!(encrypted.tag, fixture["tag"].as_str().unwrap());
        assert_eq!(decrypt(&key, "message-1", &encrypted).unwrap(), envelope);
        assert!(decrypt(&key, "message-2", &encrypted).is_err());
        assert!(decrypt(&[8_u8; SYNC_KEY_SIZE], "message-1", &encrypted).is_err());
        for field in ["nonce", "ciphertext", "tag"] {
            let mut altered = encrypted.clone();
            match field {
                "nonce" => altered.nonce.replace_range(0..1, "A"),
                "ciphertext" => altered.ciphertext.replace_range(0..1, "A"),
                "tag" => altered.tag.replace_range(0..1, "A"),
                _ => unreachable!(),
            }
            assert!(decrypt(&key, "message-1", &altered).is_err(), "{field}");
        }
    }

    #[test]
    fn validates_content_and_tombstones() {
        let live = SyncEnvelopeV1::new("m".into(), revision(), Some(b"hello".to_vec()));
        live.validate("m", 10).unwrap();
        let mut invalid = live.clone();
        invalid.content = Some(ByteBuf::from(b"other".to_vec()));
        assert!(invalid.validate("m", 10).is_err());

        let mut tombstone_revision = revision();
        tombstone_revision.is_deleted = true;
        tombstone_revision.content_hash = None;
        tombstone_revision.content_size = 0;
        SyncEnvelopeV1::new("t".into(), tombstone_revision, None)
            .validate("t", 10)
            .unwrap();
    }

    #[test]
    fn key_files_are_private_and_mnemonic_round_trips() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("private/sync.key");
        let key = generate_sync_key(&path).unwrap();
        assert_eq!(read_sync_key(&path).unwrap(), key);
        assert_eq!(
            key_from_mnemonic(&mnemonic_for_key(&key).unwrap()).unwrap(),
            key
        );
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_symbolic_link_secrets() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().unwrap();
        let real = temp.path().join("real");
        fs::write(&real, [0_u8; 32]).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            read_sync_key(&link),
            Err(CryptoError::UnsafeSecret(_))
        ));
        fs::set_permissions(&real, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_sync_key(&real),
            Err(CryptoError::UnsafePermissions(_))
        ));
    }

    #[test]
    fn generated_nonces_do_not_repeat_in_a_stress_sample() {
        use std::collections::HashSet;
        let key = [31_u8; SYNC_KEY_SIZE];
        let envelope = SyncEnvelopeV1::new("message-1".into(), revision(), Some(b"hello".to_vec()));
        let mut nonces = HashSet::new();
        for _ in 0..1_000 {
            assert!(nonces.insert(encrypt(&key, &envelope).unwrap().nonce));
        }
    }
}
