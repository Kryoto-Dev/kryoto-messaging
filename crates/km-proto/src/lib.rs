//! Wire formats for Kryoto chat.
//!
//! Hand-written `prost` messages (no `protoc` needed to build). Tags are a
//! compatibility promise: never reuse or renumber one; add new fields with new
//! tags. Unknown fields are ignored by older clients, which is how new message
//! kinds roll out without breaking anybody.
//!
//! Three layers, outermost first:
//!
//! 1. [`OuterEnvelope`] - what the server stores and forwards. Opaque.
//! 2. [`SealedContent`] - HPKE-sealed to the recipient device. Names the
//!    sender, carries the Olm message, and is padded to a size bucket.
//! 3. [`Content`] - the Olm plaintext: what the person actually sent.

pub mod gateway;

/// Current envelope format version.
pub const ENVELOPE_VERSION: u32 = 1;

/// What the gateway stores in a device's inbox. It can read none of it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OuterEnvelope {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// HPKE encapsulated key (X25519, 32 bytes).
    #[prost(bytes = "vec", tag = "2")]
    pub encapped_key: Vec<u8>,
    /// HPKE ciphertext of an encoded [`SealedContent`].
    #[prost(bytes = "vec", tag = "3")]
    pub ciphertext: Vec<u8>,
}

/// The sealed layer. Only the recipient device can open it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SealedContent {
    #[prost(uint64, tag = "1")]
    pub sender_user_id: u64,
    #[prost(uint64, tag = "2")]
    pub sender_device_id: u64,
    /// Olm message type: 0 = pre-key, 1 = normal (vodozemac's numbering).
    #[prost(uint32, tag = "3")]
    pub olm_type: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub olm_body: Vec<u8>,
    /// Zero bytes that round the encoded size up to a bucket, so the
    /// ciphertext length says little about what is inside.
    #[prost(bytes = "vec", tag = "15")]
    pub padding: Vec<u8>,
}

/// The plaintext of one chat message.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Content {
    /// 16 random bytes, chosen by the sender. Used for dedup, receipts,
    /// replies, edits and deletes.
    #[prost(bytes = "vec", tag = "1")]
    pub msg_id: Vec<u8>,
    /// Which conversation this belongs to, as the clients name it.
    #[prost(bytes = "vec", tag = "2")]
    pub conversation_id: Vec<u8>,
    /// Sender's clock, milliseconds since the Unix epoch. The server never
    /// records a send time, so this is the only one there is.
    #[prost(uint64, tag = "3")]
    pub sent_at_ms: u64,
    #[prost(oneof = "content::Body", tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22")]
    pub body: Option<content::Body>,
}

pub mod content {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "10")]
        Text(super::Text),
        #[prost(message, tag = "11")]
        Receipt(super::Receipt),
        #[prost(message, tag = "12")]
        Typing(super::Typing),
        #[prost(message, tag = "13")]
        Edit(super::Edit),
        #[prost(message, tag = "14")]
        Delete(super::Delete),
        #[prost(message, tag = "15")]
        Reaction(super::Reaction),
        #[prost(message, tag = "16")]
        Gif(super::Gif),
        #[prost(message, tag = "17")]
        Invite(super::Invite),
        #[prost(message, tag = "18")]
        GroupMeta(super::GroupMeta),
        #[prost(message, tag = "19")]
        Attachment(super::Attachment),
        #[prost(message, tag = "20")]
        Call(super::Call),
        #[prost(message, tag = "21")]
        CallLog(super::CallLog),
        #[prost(message, tag = "22")]
        Active(super::Active),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Text {
    #[prost(string, tag = "1")]
    pub text: String,
    /// msg_id of the message this replies to, or empty.
    #[prost(bytes = "vec", tag = "2")]
    pub reply_to: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ReceiptKind {
    Unspecified = 0,
    Delivered = 1,
    Read = 2,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Receipt {
    #[prost(enumeration = "ReceiptKind", tag = "1")]
    pub kind: i32,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub msg_ids: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Typing {
    #[prost(bool, tag = "1")]
    pub active: bool,
}

/// Replace the text of one of your own earlier messages.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Edit {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(string, tag = "2")]
    pub text: String,
}

/// Delete one of your own earlier messages for everyone.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Delete {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
}

/// Add (or, with `remove`, take back) an emoji reaction to a message.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Reaction {
    #[prost(bytes = "vec", tag = "1")]
    pub target: Vec<u8>,
    #[prost(string, tag = "2")]
    pub emoji: String,
    #[prost(bool, tag = "3")]
    pub remove: bool,
}

/// A GIF from a public GIF provider: the message carries where to load it
/// from, never the file. Receivers only load `url` from the provider's own
/// media host (km-core `gif_url_allowed`).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gif {
    /// "giphy" or "klipy".
    #[prost(string, tag = "1")]
    pub provider: String,
    #[prost(string, tag = "2")]
    pub id: String,
    #[prost(string, tag = "3")]
    pub url: String,
    #[prost(uint32, tag = "4")]
    pub width: u32,
    #[prost(uint32, tag = "5")]
    pub height: u32,
    /// Shown while loading, and to readers who turned automatic GIFs off.
    #[prost(string, tag = "6")]
    pub title: String,
}

/// "Come and play": a game, and when the host is in a Steam lobby (Kryoto
/// Online games), which one. No secrets: a lobby id only lets someone ask to
/// join, and the game decides. Expires quickly, because lobbies do.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Invite {
    /// kryo.to game slug.
    #[prost(string, tag = "1")]
    pub slug: String,
    #[prost(string, tag = "2")]
    pub title: String,
    /// Steam lobby id (decimal), or empty: launch together, join in game.
    #[prost(string, tag = "3")]
    pub steam_lobby: String,
    /// The host's Steam id (decimal), for steam://joinlobby while the game runs.
    #[prost(string, tag = "4")]
    pub host_steam_id: String,
    /// Sender's clock, milliseconds.
    #[prost(uint64, tag = "5")]
    pub expires_at_ms: u64,
}

/// A group's name, sent to its members whenever it is set and when someone
/// is added (the server never knows it).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GroupMeta {
    #[prost(string, tag = "1")]
    pub name: String,
}

/// A file: where the encrypted bytes are on the gateway, and what is needed
/// to fetch, check and open them (km-core `open_attachment`).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Attachment {
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Lets anyone holding the message download the ciphertext.
    #[prost(string, tag = "2")]
    pub download_token: String,
    #[prost(bytes = "vec", tag = "3")]
    pub key: Vec<u8>,
    /// SHA-256 of the ciphertext.
    #[prost(bytes = "vec", tag = "4")]
    pub sha256: Vec<u8>,
    #[prost(string, tag = "5")]
    pub name: String,
    #[prost(string, tag = "6")]
    pub mime: String,
    /// Plaintext size in bytes.
    #[prost(uint64, tag = "7")]
    pub size: u64,
    /// Images: their size in pixels (0 if not an image or unknown).
    #[prost(uint32, tag = "8")]
    pub width: u32,
    #[prost(uint32, tag = "9")]
    pub height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum CallKind {
    Unspecified = 0,
    /// "Ringing": the caller's WebRTC offer.
    Offer = 1,
    Answer = 2,
    /// One ICE candidate (trickle).
    Ice = 3,
    Hangup = 4,
    Decline = 5,
    /// Already in another call.
    Busy = 6,
    /// Mid-call, the caller's new offer after the network changed (an ICE
    /// restart); the payload is its SDP. Clients that predate it drop it.
    Restart = 7,
    /// The answer to a `Restart`.
    Restarted = 8,
    /// The sender muted their microphone (no payload).
    Muted = 9,
    /// The sender unmuted it again.
    Unmuted = 10,
}

/// A finished call, kept in the conversation so both people can see it was
/// made: sent by the caller when the call ends, stored like a message, to the
/// other person and the caller's own devices. Clients that predate it skip it.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CallLog {
    #[prost(bytes = "vec", tag = "1")]
    pub call_id: Vec<u8>,
    /// They picked up. False: missed, declined or cancelled before an answer.
    #[prost(bool, tag = "2")]
    pub answered: bool,
    /// How long it lasted once answered, in seconds.
    #[prost(uint32, tag = "3")]
    pub seconds: u32,
}

/// "I am using Kryoto on this device right now": sent now and then, only to
/// the sender's own other devices and never stored, so those leave the
/// notifications to the device in front of the person. No fields.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Active {}

/// Voice call signalling, end-to-end encrypted like everything else: the
/// WebRTC session description (with its DTLS fingerprint) and ICE candidates.
/// Because the fingerprints arrive this way, the media connection is
/// end-to-end encrypted too. Always sent ephemeral (never stored).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Call {
    #[prost(bytes = "vec", tag = "1")]
    pub call_id: Vec<u8>,
    #[prost(enumeration = "CallKind", tag = "2")]
    pub kind: i32,
    /// SDP for Offer/Answer, a candidate (JSON) for Ice.
    #[prost(string, tag = "3")]
    pub payload: String,
}
