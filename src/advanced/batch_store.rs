//! Disk-backed persistence for [`crate::utils::composition::ProofBatch`].
//!
//! Enabled with the `batch-store` feature. Not used on `wasm32` targets (no `std::fs`).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use fs4::fs_std::FileExt;

use crate::utils::composition::{BatchOperation, ProofBatch};
use crate::utils::error_handling::{ZkpError, ZkpResult};

/// File magic for batch store files (`LZB1`).
const FILE_MAGIC: &[u8; 4] = b"LZB1";
/// Payload format version (increment when breaking bincode layout).
const FORMAT_VERSION: u32 = 1;

static BATCH_STORE_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);

#[derive(serde::Serialize, serde::Deserialize)]
struct BatchFilePayloadV1 {
    operations: Vec<BatchOperation>,
}

/// Override batch store directory (created if missing). Takes precedence over `LIBZKP_BATCH_DIR`.
pub fn set_batch_store_dir(path: impl AsRef<Path>) -> ZkpResult<()> {
    let p = path.as_ref().to_path_buf();
    fs::create_dir_all(&p)
        .map_err(|e| ZkpError::StorageError(format!("create batch store directory: {}", e)))?;
    let mut g = BATCH_STORE_OVERRIDE
        .lock()
        .map_err(|_| ZkpError::StorageError("batch store lock poisoned".to_string()))?;
    *g = Some(p);
    Ok(())
}

/// Effective directory: explicit [`set_batch_store_dir`], else `LIBZKP_BATCH_DIR` if set.
pub fn get_batch_store_dir() -> Option<PathBuf> {
    if let Ok(g) = BATCH_STORE_OVERRIDE.lock() {
        if let Some(ref p) = *g {
            return Some(p.clone());
        }
    }
    std::env::var_os("LIBZKP_BATCH_DIR").map(PathBuf::from)
}

fn store_dir_required() -> ZkpResult<PathBuf> {
    get_batch_store_dir().ok_or_else(|| {
        ZkpError::ConfigError(
            "batch store not configured: set_batch_store_dir or LIBZKP_BATCH_DIR".to_string(),
        )
    })
}

pub(crate) fn batch_file_path(dir: &Path, batch_id: u64) -> PathBuf {
    dir.join(format!("batch_{:016x}.bin", batch_id))
}

fn encode_batch(batch: &ProofBatch) -> ZkpResult<Vec<u8>> {
    let payload = BatchFilePayloadV1 {
        operations: batch.operations().to_vec(),
    };
    let body = bincode::serialize(&payload)
        .map_err(|e| ZkpError::SerializationError(format!("batch file encode: {}", e)))?;
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_batch_bytes(data: &[u8]) -> ZkpResult<ProofBatch> {
    if data.len() < 8 {
        return Err(ZkpError::InvalidProofFormat(
            "batch file too short".to_string(),
        ));
    }
    if data[..4] != FILE_MAGIC[..] {
        return Err(ZkpError::InvalidProofFormat(
            "batch file: bad magic".to_string(),
        ));
    }
    let ver = u32::from_le_bytes(
        data[4..8]
            .try_into()
            .map_err(|_| ZkpError::InvalidProofFormat("batch file: bad version".to_string()))?,
    );
    if ver != FORMAT_VERSION {
        return Err(ZkpError::InvalidProofFormat(format!(
            "batch file: unsupported version {}",
            ver
        )));
    }
    let payload: BatchFilePayloadV1 = bincode::deserialize(&data[8..])
        .map_err(|e| ZkpError::SerializationError(format!("batch file decode: {}", e)))?;
    Ok(ProofBatch::from_operations(payload.operations))
}

/// Write `batch` to the store directory for `batch_id` (exclusive lock, atomic replace).
pub fn write_batch_file(dir: &Path, batch_id: u64, batch: &ProofBatch) -> ZkpResult<()> {
    let final_path = batch_file_path(dir, batch_id);
    let tmp_path = dir.join(format!(".batch_{:016x}.tmp", batch_id));
    let bytes = encode_batch(batch)?;

    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| ZkpError::StorageError(format!("open temp batch file: {}", e)))?;
        f.lock_exclusive()
            .map_err(|e| ZkpError::StorageError(format!("lock temp batch file: {}", e)))?;
        f.write_all(&bytes)
            .map_err(|e| ZkpError::StorageError(format!("write temp batch file: {}", e)))?;
        f.sync_all()
            .map_err(|e| ZkpError::StorageError(format!("sync temp batch file: {}", e)))?;
    }

    fs::rename(&tmp_path, &final_path)
        .map_err(|e| ZkpError::StorageError(format!("rename batch file: {}", e)))?;
    Ok(())
}

/// Read a batch from the store directory (shared lock).
pub fn read_batch_file(dir: &Path, batch_id: u64) -> ZkpResult<ProofBatch> {
    let path = batch_file_path(dir, batch_id);
    let mut f = OpenOptions::new()
        .read(true)
        .open(&path)
        .map_err(|e| ZkpError::StorageError(format!("open batch file: {}", e)))?;
    f.lock_shared()
        .map_err(|e| ZkpError::StorageError(format!("lock batch file: {}", e)))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| ZkpError::StorageError(format!("read batch file: {}", e)))?;
    decode_batch_bytes(&buf)
}

/// Remove the on-disk file for `batch_id` if the store is configured and the file exists.
pub fn delete_batch_file_if_configured(batch_id: u64) -> ZkpResult<()> {
    let Some(dir) = get_batch_store_dir() else {
        return Ok(());
    };
    let path = batch_file_path(&dir, batch_id);
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|e| ZkpError::StorageError(format!("remove batch file: {}", e)))?;
    }
    Ok(())
}

/// Persist when a store directory is configured; no-op otherwise.
pub fn persist_batch_if_configured(batch_id: u64, batch: &ProofBatch) -> ZkpResult<()> {
    let Some(dir) = get_batch_store_dir() else {
        return Ok(());
    };
    write_batch_file(&dir, batch_id, batch)
}

/// List `batch_id`s that have files in the configured store directory.
pub fn list_batch_ids_in_store() -> ZkpResult<Vec<u64>> {
    let dir = store_dir_required()?;
    let mut ids = Vec::new();
    for ent in fs::read_dir(&dir)
        .map_err(|e| ZkpError::StorageError(format!("read batch store: {}", e)))?
    {
        let ent = ent.map_err(|e| ZkpError::StorageError(format!("batch store entry: {}", e)))?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix("batch_") else {
            continue;
        };
        let Some(hexpart) = rest.strip_suffix(".bin") else {
            continue;
        };
        if let Ok(id) = u64::from_str_radix(hexpart, 16) {
            ids.push(id);
        }
    }
    ids.sort_unstable();
    Ok(ids)
}

/// Write encoded batch bytes to an arbitrary path (for backup / migration).
pub fn export_proof_batch_to_path(batch: &ProofBatch, path: impl AsRef<Path>) -> ZkpResult<()> {
    let bytes = encode_batch(batch)?;
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| ZkpError::StorageError(format!("create export parent: {}", e)))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)
            .map_err(|e| ZkpError::StorageError(format!("open export temp: {}", e)))?;
        f.lock_exclusive()
            .map_err(|e| ZkpError::StorageError(format!("lock export temp: {}", e)))?;
        f.write_all(&bytes)
            .map_err(|e| ZkpError::StorageError(format!("write export: {}", e)))?;
        f.sync_all()
            .map_err(|e| ZkpError::StorageError(format!("sync export: {}", e)))?;
    }
    fs::rename(&tmp, path).map_err(|e| ZkpError::StorageError(format!("rename export: {}", e)))?;
    Ok(())
}

/// Read a batch file from any path (same format as store files).
pub fn import_proof_batch_from_path(path: impl AsRef<Path>) -> ZkpResult<ProofBatch> {
    let path = path.as_ref();
    let mut f =
        File::open(path).map_err(|e| ZkpError::StorageError(format!("open import: {}", e)))?;
    f.lock_shared()
        .map_err(|e| ZkpError::StorageError(format!("lock import: {}", e)))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| ZkpError::StorageError(format!("read import: {}", e)))?;
    decode_batch_bytes(&buf)
}
