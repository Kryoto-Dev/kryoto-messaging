//! The desktop's encrypted chat database.
//!
//! One SQLCipher file per signed-in account. The 256-bit key is random, made
//! once, and kept in the OS secure store (Windows Credential Manager, Linux
//! Secret Service) by the desktop app; this crate only ever receives it. With
//! SQLCipher the whole file is encrypted (pages, indexes, the search index
//! and the WAL), so nothing about the conversations is readable on disk.
//!
//! This crate holds the cryptographic state (device, trust pins, master key).
//! Message history tables arrive with the client layer.

#[cfg(not(any(feature = "sqlcipher", feature = "plain-sqlite-dev")))]
compile_error!("enable the `sqlcipher` feature (default)");

#[cfg(all(feature = "plain-sqlite-dev", not(feature = "sqlcipher"), not(debug_assertions)))]
compile_error!("`plain-sqlite-dev` stores chat state unencrypted and must never be built in release mode");

mod messages;

pub use messages::{item_of, ConversationRow, MessageRow, NewMessage, ReactionRow, Status};

use std::path::Path;

use km_core::{CoreError, LocalDevice, MasterKey, TrustStore};
use rusqlite::{params, Connection, OptionalExtension};
use zeroize::Zeroizing;

const SCHEMA_VERSION: i64 = 2;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("wrong key, or not a Kryoto chat database")]
    WrongKey,
    #[error("saved chat state is corrupt")]
    Corrupt,
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error(transparent)]
    Core(#[from] CoreError),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Whether this build actually encrypts. The desktop refuses to turn chat on
/// when this is false outside a debug build.
pub const fn is_encrypted() -> bool {
    cfg!(feature = "sqlcipher")
}

pub struct Store {
    conn: Connection,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Store(..)")
    }
}

impl Store {
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self> {
        Self::init(Connection::open(path)?, key)
    }

    pub fn open_in_memory(key: &[u8; 32]) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, key)
    }

    fn init(conn: Connection, key: &[u8; 32]) -> Result<Self> {
        apply_key(&conn, "key", key)?;
        // The first real read is where a wrong key shows up.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
            .map_err(|_| StoreError::WrongKey)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA secure_delete = ON;
             PRAGMA foreign_keys = ON;",
        )?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let version: i64 = self.conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            // Written by a newer app; do not touch it.
            return Err(StoreError::Corrupt);
        }
        if version < 1 {
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS kv (
                   name  TEXT PRIMARY KEY,
                   value BLOB NOT NULL
                 );
                 PRAGMA user_version = 1;",
            )?;
        }
        if version < 2 {
            self.conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS conversations (
                   id            BLOB PRIMARY KEY,
                   kind          TEXT NOT NULL DEFAULT 'dm',
                   peer_user_id  INTEGER,
                   last_at       INTEGER NOT NULL DEFAULT 0,
                   unread        INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE IF NOT EXISTS messages (
                   msg_id          BLOB PRIMARY KEY,
                   conversation_id BLOB NOT NULL,
                   sender_user     INTEGER NOT NULL,
                   sender_device   INTEGER NOT NULL,
                   outgoing        INTEGER NOT NULL,
                   sent_at         INTEGER NOT NULL,
                   received_at     INTEGER NOT NULL,
                   kind            TEXT NOT NULL,
                   body            TEXT NOT NULL DEFAULT '',
                   reply_to        BLOB,
                   edited_at       INTEGER,
                   deleted         INTEGER NOT NULL DEFAULT 0,
                   status          TEXT NOT NULL DEFAULT 'received'
                 );
                 CREATE INDEX IF NOT EXISTS messages_conversation_idx
                   ON messages (conversation_id, sent_at, msg_id);
                 CREATE TABLE IF NOT EXISTS reactions (
                   msg_id   BLOB NOT NULL,
                   user_id  INTEGER NOT NULL,
                   emoji    TEXT NOT NULL,
                   PRIMARY KEY (msg_id, user_id, emoji)
                 );
                 PRAGMA user_version = 2;",
            )?;
        }
        Ok(())
    }

    /// Re-encrypt the whole database under a new key.
    pub fn rekey(&self, new_key: &[u8; 32]) -> Result<()> {
        apply_key(&self.conn, "rekey", new_key)
    }

    /// The SQLite connection, for the message tables in `messages.rs`.
    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Small settings values (not secrets): read receipts on/off and the like.
    pub fn set_setting(&self, name: &str, value: &str) -> Result<()> {
        self.put(&format!("setting:{name}"), value.as_bytes())
    }

    pub fn setting(&self, name: &str) -> Result<Option<String>> {
        Ok(self
            .get(&format!("setting:{name}"))?
            .and_then(|v| String::from_utf8(v.to_vec()).ok()))
    }

    fn put(&self, name: &str, value: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv (name, value) VALUES (?1, ?2)
             ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            params![name, value],
        )?;
        Ok(())
    }

    fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE name = ?1", params![name], |r| r.get::<_, Vec<u8>>(0))
            .optional()?
            .map(Zeroizing::new))
    }

    pub fn save_device(&self, device: &LocalDevice) -> Result<()> {
        let snap = device.snapshot()?;
        self.put("device", snap.as_bytes())
    }

    pub fn load_device(&self) -> Result<Option<LocalDevice>> {
        let Some(bytes) = self.get("device")? else { return Ok(None) };
        let text = std::str::from_utf8(&bytes).map_err(|_| StoreError::Corrupt)?;
        Ok(Some(LocalDevice::restore(text)?))
    }

    pub fn save_trust(&self, trust: &TrustStore) -> Result<()> {
        let json = Zeroizing::new(serde_json_vec(trust)?);
        self.put("trust", &json)
    }

    pub fn load_trust(&self) -> Result<TrustStore> {
        match self.get("trust")? {
            None => Ok(TrustStore::new()),
            Some(bytes) => serde_json_from(&bytes),
        }
    }

    pub fn save_master_key(&self, key: &MasterKey) -> Result<()> {
        self.put("master_key", key.to_secret_bytes().as_slice())
    }

    pub fn load_master_key(&self) -> Result<Option<MasterKey>> {
        let Some(bytes) = self.get("master_key")? else { return Ok(None) };
        let arr: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| StoreError::Corrupt)?;
        Ok(Some(MasterKey::from_secret_bytes(arr)))
    }
}

#[cfg(feature = "sqlcipher")]
fn apply_key(conn: &Connection, pragma: &str, key: &[u8; 32]) -> Result<()> {
    // Raw key syntax: SQLCipher uses the 32 bytes directly, no passphrase KDF
    // (the key is already uniformly random).
    let stmt = Zeroizing::new(format!("PRAGMA {pragma} = \"x'{}'\";", hex::encode(key)));
    conn.execute_batch(&stmt)?;
    Ok(())
}

#[cfg(not(feature = "sqlcipher"))]
fn apply_key(_conn: &Connection, _pragma: &str, _key: &[u8; 32]) -> Result<()> {
    Ok(())
}

// TrustStore is serde; keep the JSON plumbing in one place.
fn serde_json_vec<T: serde::Serialize>(v: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(v).map_err(|_| StoreError::Corrupt)
}

fn serde_json_from<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt)
}
