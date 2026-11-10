//! Kryoto chat core: everything cryptographic, nothing else.
//!
//! No I/O, no clock, no storage. The desktop app (natively) and the web client
//! (as WebAssembly) drive it and persist what [`LocalDevice::snapshot`] and
//! [`TrustStore`] give them inside their own encrypted stores. A UI never sees
//! a private key: nothing in this crate returns one except the explicitly named
//! persistence calls, which only the storage layer uses.
//!
//! Primitives all come from maintained, reviewed libraries:
//! - Olm / Double Ratchet: `vodozemac` (audited, Matrix.org)
//! - Sealed outer layer: RFC 9180 HPKE via `hpke` (X25519, HKDF-SHA256, ChaCha20-Poly1305)
//! - Signatures: Ed25519 via `vodozemac` (ed25519-dalek)
//! - Key backup: XChaCha20-Poly1305 via `chacha20poly1305` (RustCrypto)
//! - Safety numbers: Signal's numeric fingerprint construction over SHA-512
//!
//! See `FRIENDS-AND-CHAT.md` in the Kryoto workspace for the full design.

mod attachment;
mod backup;
pub mod chat;
mod device;
mod error;
mod fingerprint;
pub mod history;
mod keys;
mod trust;

pub use attachment::{open_attachment, seal_attachment, SealedAttachment, MAX_ATTACHMENT};
pub use backup::{open_backup, seal_backup, RecoveryKey};
pub use device::{new_message_id, Inbound, LocalDevice};
pub use error::{CoreError, Result};
pub use fingerprint::{display_groups, qr_payload, safety_number, verify_qr};
pub use keys::{
    gateway_auth_bytes, verify_gateway_proof, DeviceKeys, DeviceKind, MasterKey, SignedDevice, SignedPrekey,
};
pub use km_proto as proto;
pub use trust::{CheckedDevices, TrustLevel, TrustStore, TrustedDevice, UserDevices};
