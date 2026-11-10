//! Past messages from one of your devices to another (KB-0254).
//!
//! The server keeps no history: a message is encrypted to the devices that
//! exist when it is sent, and each copy is deleted once delivered. So a new
//! device (first set up, or restored with the recovery code) starts empty.
//! It asks the account's other devices for their history (`HistoryRequest`),
//! one of them sends what it holds (`HistoryChunk`s, encrypted to that one
//! device like any message), and the new device merges it into its own store.
//!
//! This module is the part both clients share: which rows travel, how they
//! are cut into chunks that fit the gateway's envelope limit, what a receiver
//! accepts, and how a received row merges with one already stored. The
//! clients do the sending, the waiting and the asking.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use km_proto::{content::Body, Content, HistoryAck, HistoryChunk, HistoryGroup, HistoryItem, HistoryReaction, HistoryRequest};
use prost::Message as _;
use serde_json::Value;

use crate::chat::{
    attachment_valid, call_log_valid, dm_conversation_id, dm_peer, gif_url_allowed, group_of, invite_valid, GROUP_NAME_LIMIT,
    REACTION_LIMIT, SUPPORTER_TEXT_LIMIT,
};

/// Bytes in a transfer id.
pub const TRANSFER_ID_LEN: usize = 16;
/// The most a chunk's whole `Content` may encode to. The sealed layer's
/// largest padding bucket is 65,280 bytes (the gateway takes envelopes up to
/// 64 KiB); an Olm pre-key message adds about 200 bytes and the sealed layer
/// about 30, so this leaves a margin of several KiB.
pub const CHUNK_BUDGET: usize = 60_000;
/// A stored body bigger than this never travels (none is: text is at most
/// 8,000 characters, the other kinds are short JSON). It keeps one row
/// always small enough to fit a chunk on its own.
pub const MAX_BODY: usize = 32 * 1024;
/// The most chunks one transfer may have (about 600 MB), and items or groups
/// one chunk may carry: bounds what a receiver does for one message.
pub const MAX_CHUNKS: u32 = 10_000;
pub const MAX_ITEMS_PER_CHUNK: usize = 10_000;
pub const MAX_GROUPS: usize = 256;
/// Longest device name a request may carry.
pub const DEVICE_NAME_LIMIT: usize = 48;
const MAX_REACTIONS: usize = 64;
const MAX_REACTORS: usize = 64;
/// The kinds of stored rows that travel.
pub const KINDS: [&str; 5] = ["text", "gif", "invite", "file", "call"];

/// The conversation history messages travel in: the account's own.
pub fn own_conversation(me: u64) -> Vec<u8> {
    dm_conversation_id(me, me)
}

pub fn request_valid(r: &HistoryRequest) -> bool {
    r.transfer_id.len() == TRANSFER_ID_LEN && r.device_name.chars().count() <= DEVICE_NAME_LIMIT && !r.device_name.chars().any(char::is_control)
}

pub fn ack_valid(a: &HistoryAck) -> bool {
    a.transfer_id.len() == TRANSFER_ID_LEN && a.next <= MAX_CHUNKS
}

/// A chunk's frame, before its rows are looked at one by one.
pub fn chunk_valid(c: &HistoryChunk) -> bool {
    c.transfer_id.len() == TRANSFER_ID_LEN
        && c.total >= 1
        && c.total <= MAX_CHUNKS
        && c.index < c.total
        && c.items.len() <= MAX_ITEMS_PER_CHUNK
        && c.groups.len() <= MAX_GROUPS
}

fn status_ok(outgoing: bool, status: &str) -> bool {
    if outgoing {
        matches!(status, "sent" | "delivered" | "read")
    } else {
        matches!(status, "received" | "read")
    }
}

fn digits(v: &Value, max: usize) -> bool {
    v.as_str().is_some_and(|s| s.len() <= max && s.bytes().all(|b| b.is_ascii_digit()))
}

/// Lowercase or uppercase hex to bytes (km-core keeps its dependencies few).
fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

fn hex_of_len(v: &Value, len: usize) -> bool {
    v.as_str().is_some_and(|s| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A stored body of `kind`, checked the way the message itself was when it
/// arrived: what a client could not have stored from a real message is
/// refused (a game invite's ids end up on a command line, a file's token in
/// a URL).
fn body_valid(kind: &str, body: &str) -> bool {
    if body.len() > MAX_BODY {
        return false;
    }
    if kind == "text" {
        return body.chars().count() <= SUPPORTER_TEXT_LIMIT;
    }
    let Ok(v) = serde_json::from_str::<Value>(body) else { return false };
    let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    let n = |k: &str| v[k].as_u64().unwrap_or(0);
    match kind {
        "gif" => gif_url_allowed(&s("provider"), &s("url")) && s("title").chars().count() <= 200,
        "invite" => invite_valid(&km_proto::Invite {
            slug: s("slug"),
            title: s("title"),
            steam_lobby: s("steamLobby"),
            host_steam_id: s("hostSteamId"),
            expires_at_ms: n("expiresAt"),
        }),
        "file" => {
            let (Some(key), Some(sha256)) = (unhex(&s("key")), unhex(&s("sha256"))) else { return false };
            let id = match &v["id"] {
                Value::String(x) => x.parse::<u64>().unwrap_or(0),
                other => other.as_u64().unwrap_or(0),
            };
            attachment_valid(&km_proto::Attachment {
                id,
                download_token: s("token"),
                key,
                sha256,
                name: s("name"),
                mime: s("mime"),
                size: n("size"),
                width: 0,
                height: 0,
            })
        }
        "call" => {
            let answered = v["answered"].as_bool().unwrap_or(false);
            let seconds = n("seconds").min(u64::from(u32::MAX)) as u32;
            hex_of_len(&v["callId"], 32)
                && digits(&v["caller"], 20)
                && call_log_valid(&km_proto::CallLog { call_id: vec![0; 16], answered, seconds })
        }
        _ => false,
    }
}

/// Is this a row that may travel, and that a receiver may store? `me` is the
/// account: a row must be from one of its conversations, and its own
/// messages are exactly those it sent.
pub fn item_valid(me: u64, i: &HistoryItem) -> bool {
    if i.msg_id.len() != 16 || !KINDS.contains(&i.kind.as_str()) || !status_ok(i.outgoing, &i.status) {
        return false;
    }
    if i.outgoing != (i.sender_user == me) {
        return false;
    }
    match (dm_peer(&i.conversation_id, me), group_of(&i.conversation_id)) {
        // The account's own conversation carries only these control messages.
        (Some(peer), _) if peer == me => return false,
        (Some(peer), _) if i.sender_user != me && i.sender_user != peer => return false,
        (Some(_), _) => {}
        (None, Some(_)) => {
            if i.kind == "call" {
                return false;
            }
        }
        (None, None) => return false,
    }
    if !i.reply_to.is_empty() && i.reply_to.len() != 16 {
        return false;
    }
    if i.deleted {
        if !i.body.is_empty() || !i.reactions.is_empty() {
            return false;
        }
    } else if !body_valid(&i.kind, &i.body) {
        return false;
    }
    i.reactions.len() <= MAX_REACTIONS
        && i.reactions.iter().all(|r| {
            !r.emoji.is_empty() && r.emoji.chars().count() <= REACTION_LIMIT && !r.user_ids.is_empty() && r.user_ids.len() <= MAX_REACTORS
        })
}

fn group_valid(g: &HistoryGroup) -> bool {
    g.group_id != 0 && !g.name.trim().is_empty() && g.name.chars().count() <= GROUP_NAME_LIMIT
}

/// Bytes a value adds as one field of a message (key, length, itself).
fn field_len(len: usize) -> usize {
    1 + prost::encoding::encoded_len_varint(len as u64) + len
}

/// Everything in a chunk's `Content` but its rows and groups: the message id
/// (18), the conversation (21), the send time (11), the body's key and
/// length (2 + 3), and the chunk's transfer id, index and total (18 + 6 + 6).
const CHUNK_OVERHEAD: usize = 18 + 21 + 11 + 5 + 18 + 6 + 6;

/// Cut `items` (and the account's group names) into chunks, oldest first.
///
/// Rows that may not travel are left out (unsent messages: the device that
/// holds them still sends them, and a copy reaches the new device then).
/// Each chunk's `Content` encodes to at most [`CHUNK_BUDGET`] bytes.
/// Always at least one chunk, so an empty history still says "that is all".
pub fn chunks(me: u64, transfer_id: &[u8], items: Vec<HistoryItem>, groups: Vec<HistoryGroup>) -> Vec<HistoryChunk> {
    let mut seen = BTreeSet::new();
    let mut rows: Vec<HistoryItem> = items.into_iter().filter(|i| item_valid(me, i)).collect();
    rows.sort_by(|a, b| (a.sent_at_ms, &a.msg_id).cmp(&(b.sent_at_ms, &b.msg_id)));
    rows.retain(|i| seen.insert(i.msg_id.clone()));

    let mut names = BTreeMap::new();
    for g in groups.into_iter().filter(group_valid) {
        names.insert(g.group_id, g);
    }
    let groups: Vec<HistoryGroup> = names.into_values().take(MAX_GROUPS).collect();

    let mut out = Vec::new();
    let mut size = CHUNK_OVERHEAD + groups.iter().map(|g| field_len(g.encoded_len())).sum::<usize>();
    let mut current = HistoryChunk { transfer_id: transfer_id.to_vec(), index: 0, total: 0, items: Vec::new(), groups };
    for item in rows {
        let cost = field_len(item.encoded_len());
        if !current.items.is_empty() && (size + cost > CHUNK_BUDGET || current.items.len() >= MAX_ITEMS_PER_CHUNK) {
            let next = HistoryChunk { transfer_id: transfer_id.to_vec(), index: 0, total: 0, items: Vec::new(), groups: Vec::new() };
            out.push(std::mem::replace(&mut current, next));
            size = CHUNK_OVERHEAD;
        }
        size += cost;
        current.items.push(item);
    }
    out.push(current);
    let total = out.len() as u32;
    for (i, c) in out.iter_mut().enumerate() {
        c.index = i as u32;
        c.total = total;
    }
    out
}

/// A history message as `Content`, in the account's own conversation.
pub fn content(me: u64, body: Body, sent_at_ms: u64) -> Content {
    Content { msg_id: crate::new_message_id().to_vec(), conversation_id: own_conversation(me), sent_at_ms, body: Some(body) }
}

fn rank(outgoing: bool, status: &str) -> u8 {
    match (outgoing, status) {
        (true, "sent") => 1,
        (true, "delivered") => 2,
        (true, "read") => 3,
        (false, "received") => 1,
        (false, "read") => 2,
        _ => 0,
    }
}

/// What to store for a received row, given the one already here (if any).
/// `None` when nothing would change.
///
/// Both devices saw the same conversation, each from when it existed, so a
/// row is only ever more complete on one side: a delete wins, the later edit
/// wins, a status only moves forward, reactions are the union.
pub fn merge(existing: Option<&HistoryItem>, incoming: &HistoryItem) -> Option<HistoryItem> {
    let Some(old) = existing else { return Some(incoming.clone()) };
    // Another message with the same id would be a forgery: keep ours.
    if old.conversation_id != incoming.conversation_id || old.sender_user != incoming.sender_user || old.kind != incoming.kind {
        return None;
    }
    let mut m = old.clone();
    if incoming.deleted && !m.deleted {
        m.deleted = true;
        m.body.clear();
        m.reactions.clear();
    }
    if !m.deleted {
        if incoming.edited_at_ms > m.edited_at_ms {
            m.body = incoming.body.clone();
            m.edited_at_ms = incoming.edited_at_ms;
        }
        let mut by: BTreeMap<String, BTreeSet<u64>> = BTreeMap::new();
        for r in m.reactions.iter().chain(incoming.reactions.iter()) {
            by.entry(r.emoji.clone()).or_default().extend(r.user_ids.iter().copied());
        }
        m.reactions = by.into_iter().map(|(emoji, users)| HistoryReaction { emoji, user_ids: users.into_iter().collect() }).collect();
    }
    if rank(m.outgoing, &incoming.status) > rank(m.outgoing, &m.status) {
        m.status = incoming.status.clone();
    }
    (m != *old).then_some(m)
}

/// A received chunk's rows against the store: the rows to write, each once,
/// oldest first. Rows that may not be stored are dropped. `stored` looks a
/// message up by id.
pub fn merge_rows(me: u64, incoming: Vec<HistoryItem>, mut stored: impl FnMut(&[u8]) -> Option<HistoryItem>) -> Vec<HistoryItem> {
    // Duplicates inside one batch merge with each other first.
    let mut batch: HashMap<Vec<u8>, HistoryItem> = HashMap::new();
    for item in incoming.into_iter().filter(|i| item_valid(me, i)) {
        let merged = match batch.get(&item.msg_id) {
            Some(prev) => merge(Some(prev), &item).unwrap_or_else(|| prev.clone()),
            None => item,
        };
        batch.insert(merged.msg_id.clone(), merged);
    }
    let mut out: Vec<HistoryItem> = batch.into_values().filter_map(|i| merge(stored(&i.msg_id).as_ref(), &i)).collect();
    out.sort_by(|a, b| (a.sent_at_ms, &a.msg_id).cmp(&(b.sent_at_ms, &b.msg_id)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::group_conversation_id;

    const ME: u64 = 5;
    const PEER: u64 = 9;

    fn row(n: u8, at: u64, text: &str) -> HistoryItem {
        HistoryItem {
            msg_id: vec![n; 16],
            conversation_id: dm_conversation_id(ME, PEER),
            sender_user: PEER,
            sender_device: 90,
            outgoing: false,
            sent_at_ms: at,
            received_at_ms: at + 1,
            kind: "text".into(),
            body: text.into(),
            reply_to: vec![],
            edited_at_ms: 0,
            deleted: false,
            status: "read".into(),
            reactions: vec![],
        }
    }

    fn mine(n: u8, at: u64, status: &str) -> HistoryItem {
        HistoryItem { sender_user: ME, sender_device: 50, outgoing: true, status: status.into(), ..row(n, at, "from me") }
    }

    fn chunk_content_len(c: &HistoryChunk) -> usize {
        Content {
            msg_id: vec![0xff; 16],
            conversation_id: own_conversation(u64::MAX),
            sent_at_ms: u64::MAX,
            body: Some(Body::HistoryChunk(HistoryChunk { index: u32::MAX, total: u32::MAX, ..c.clone() })),
        }
        .encoded_len()
    }

    #[test]
    fn an_empty_history_is_one_empty_chunk() {
        let c = chunks(ME, &[1; 16], vec![], vec![]);
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].index, c[0].total), (0, 1));
        assert!(c[0].items.is_empty());
        assert!(chunk_valid(&c[0]));
    }

    #[test]
    fn chunks_fit_the_budget_keep_order_and_lose_nothing() {
        // 3,000 rows of up to 8,000 characters, out of order: many chunks.
        let mut items = Vec::new();
        for i in 0..3000u32 {
            let len = [5usize, 300, 8000, 40][i as usize % 4];
            let mut r = row(0, u64::from(3000 - i), &"é".repeat(len));
            r.msg_id = [i.to_be_bytes().to_vec(), vec![7; 12]].concat();
            items.push(r);
        }
        let groups = vec![HistoryGroup { group_id: 3, name: "Lethal crew".into() }];
        let c = chunks(ME, &[1; 16], items, groups);
        assert!(c.len() > 10, "{} chunks", c.len());
        let mut last = 0;
        let mut count = 0;
        for (i, ch) in c.iter().enumerate() {
            assert_eq!((ch.index, ch.total), (i as u32, c.len() as u32));
            assert!(chunk_valid(ch));
            let len = chunk_content_len(ch);
            assert!(len <= CHUNK_BUDGET, "chunk {i} encodes to {len}");
            assert_eq!(ch.groups.is_empty(), i > 0, "group names ride in the first chunk only");
            for it in &ch.items {
                assert!(it.sent_at_ms >= last, "oldest first across chunks");
                last = it.sent_at_ms;
                count += 1;
            }
        }
        assert_eq!(count, 3000);
    }

    #[test]
    fn the_fullest_chunk_still_seals_under_the_gateway_limit() {
        use crate::{DeviceKind, LocalDevice, MasterKey, TrustStore, UserDevices};
        // Rows of the largest kind until one chunk is as full as it gets.
        let items: Vec<HistoryItem> = (0..40u8).map(|n| row(n, u64::from(n), &"\u{1F600}".repeat(2000))).collect();
        let c = chunks(ME, &[1; 16], items, vec![]);
        let fullest = c.iter().max_by_key(|ch| chunk_content_len(ch)).unwrap();
        assert!(chunk_content_len(fullest) > CHUNK_BUDGET - 8_200, "the test needs a nearly full chunk");

        // A brand-new session: the first message is the bigger pre-key kind.
        let mut a = LocalDevice::new(ME, DeviceKind::Desktop);
        a.set_device_id(1).unwrap();
        let mut b = LocalDevice::new(ME, DeviceKind::Web);
        b.set_device_id(2).unwrap();
        let master = MasterKey::generate();
        let mut trust = TrustStore::new();
        trust.pin_own(ME, master.public_key());
        let ub = UserDevices { user_id: ME, master_key: master.public_key(), devices: vec![master.certify(&b.keys())] };
        let to_b = trust.check(&ub).unwrap().devices.remove(0);
        let ua = UserDevices { user_id: ME, master_key: master.public_key(), devices: vec![master.certify(&a.keys())] };
        let from_a = trust.check(&ua).unwrap().devices.remove(0);
        let pk = b.publish_prekeys(1, false).unwrap().remove(0);
        let body = content(ME, Body::HistoryChunk(fullest.clone()), 1);
        let envelope = a.encrypt(&to_b, Some(&pk), &body).unwrap();
        assert!(envelope.len() <= 65_536, "envelope {} bytes", envelope.len());
        let got = b.decrypt(&envelope, |_, _| Some(from_a.clone())).unwrap();
        assert_eq!(got.content, body);
    }

    #[test]
    fn unsent_foreign_and_malformed_rows_never_travel() {
        let ok = row(1, 1, "hi");
        let invalid = [
            mine(2, 2, "sending"),
            mine(3, 3, "failed"),
            HistoryItem { conversation_id: dm_conversation_id(7, 8), ..row(4, 4, "x") },
            HistoryItem { conversation_id: own_conversation(ME), ..row(5, 5, "x") },
            HistoryItem { sender_user: 77, ..row(6, 6, "x") },
            HistoryItem { outgoing: true, ..row(7, 7, "x") },
            HistoryItem { msg_id: vec![1; 15], ..row(8, 8, "x") },
            HistoryItem { kind: "script".into(), ..row(9, 9, "x") },
            HistoryItem { body: "x".repeat(8001), ..row(10, 10, "") },
            HistoryItem { deleted: true, ..row(11, 11, "still here") },
            HistoryItem { kind: "invite".into(), ..row(12, 12, r#"{"slug":"a","title":"A","steamLobby":"1 -exec","hostSteamId":"","expiresAt":1}"#) },
            HistoryItem { kind: "gif".into(), ..row(13, 13, r#"{"provider":"giphy","url":"https://evil.example/a.gif","title":""}"#) },
            HistoryItem { kind: "call".into(), conversation_id: group_conversation_id(3), ..row(14, 14, "{}") },
        ];
        assert!(item_valid(ME, &ok));
        for bad in &invalid {
            assert!(!item_valid(ME, bad), "{bad:?}");
        }
        let c = chunks(ME, &[1; 16], [vec![ok.clone()], invalid.to_vec()].concat(), vec![]);
        assert_eq!(c[0].items, vec![ok]);

        let good = [
            HistoryItem { kind: "invite".into(), ..row(20, 1, r#"{"slug":"lethal-company","title":"Lethal Company","steamLobby":"109775241075364289","hostSteamId":"","expiresAt":5}"#) },
            HistoryItem { kind: "gif".into(), ..row(21, 1, r#"{"provider":"giphy","id":"a","url":"https://media.giphy.com/a.gif","width":1,"height":1,"title":"cat"}"#) },
            HistoryItem {
                kind: "file".into(),
                ..row(22, 1, &format!(r#"{{"id":"5","token":"{}","key":"{}","sha256":"{}","name":"a.png","mime":"image/png","size":9,"width":0,"height":0}}"#, "ab".repeat(16), "11".repeat(32), "22".repeat(32)))
            },
            HistoryItem { kind: "call".into(), ..row(23, 1, &format!(r#"{{"callId":"{}","answered":true,"seconds":30,"caller":"9"}}"#, "cd".repeat(16))) },
            HistoryItem { conversation_id: group_conversation_id(3), sender_user: 77, ..row(24, 1, "in a group") },
            HistoryItem { deleted: true, ..row(25, 1, "") },
            mine(26, 1, "delivered"),
        ];
        for g in &good {
            assert!(item_valid(ME, g), "{g:?}");
        }
    }

    #[test]
    fn merging_dedupes_and_completes_rows() {
        let base = row(1, 10, "hello");
        assert_eq!(merge(None, &base), Some(base.clone()), "new rows are taken");
        assert_eq!(merge(Some(&base), &base), None, "the same row again changes nothing");

        let edited = HistoryItem { body: "hello!".into(), edited_at_ms: 20, ..base.clone() };
        assert_eq!(merge(Some(&base), &edited).unwrap().body, "hello!");
        assert_eq!(merge(Some(&edited), &base), None, "an older text never replaces a newer edit");

        let gone = HistoryItem { deleted: true, body: String::new(), ..base.clone() };
        let m = merge(Some(&edited), &gone).unwrap();
        assert!(m.deleted && m.body.is_empty());
        assert_eq!(merge(Some(&gone), &edited), None, "a delete is never undone");

        let sent = mine(2, 10, "sent");
        let read = mine(2, 10, "read");
        assert_eq!(merge(Some(&sent), &read).unwrap().status, "read");
        assert_eq!(merge(Some(&read), &sent), None, "status only moves forward");

        let unread = HistoryItem { status: "received".into(), ..base.clone() };
        assert_eq!(merge(Some(&unread), &base).unwrap().status, "read", "read elsewhere counts");

        let r1 = HistoryItem { reactions: vec![HistoryReaction { emoji: "🔥".into(), user_ids: vec![9] }], ..base.clone() };
        let r2 = HistoryItem { reactions: vec![HistoryReaction { emoji: "🔥".into(), user_ids: vec![5] }, HistoryReaction { emoji: "👍".into(), user_ids: vec![9] }], ..base.clone() };
        let m = merge(Some(&r1), &r2).unwrap();
        assert_eq!(m.reactions.len(), 2);
        assert_eq!(m.reactions.iter().find(|r| r.emoji == "🔥").unwrap().user_ids, vec![5, 9]);

        let forged = HistoryItem { sender_user: ME, outgoing: true, status: "sent".into(), ..base.clone() };
        assert_eq!(merge(Some(&base), &forged), None, "a row with the same id but another author is not ours to take");
    }

    #[test]
    fn a_batch_writes_each_new_or_changed_row_once_in_order() {
        let stored: HashMap<Vec<u8>, HistoryItem> = [row(1, 10, "kept"), row(2, 20, "old")].into_iter().map(|r| (r.msg_id.clone(), r)).collect();
        let incoming = vec![
            row(3, 30, "new"),
            row(1, 10, "kept"),
            HistoryItem { body: "edited".into(), edited_at_ms: 25, ..row(2, 20, "old") },
            row(3, 30, "new"),
            row(0, 5, "older"),
            mine(4, 1, "sending"),
        ];
        let out = merge_rows(ME, incoming, |id| stored.get(id).cloned());
        let ids: Vec<u8> = out.iter().map(|r| r.msg_id[0]).collect();
        assert_eq!(ids, vec![0, 2, 3], "row 1 is unchanged, row 4 was never sent, row 3 once");
        assert_eq!(out[1].body, "edited");
    }

    #[test]
    fn control_messages_are_checked() {
        assert!(request_valid(&HistoryRequest { transfer_id: vec![1; 16], device_name: "Chrome on Windows".into() }));
        assert!(!request_valid(&HistoryRequest { transfer_id: vec![1; 15], device_name: String::new() }));
        assert!(!request_valid(&HistoryRequest { transfer_id: vec![1; 16], device_name: "x".repeat(49) }));
        assert!(!request_valid(&HistoryRequest { transfer_id: vec![1; 16], device_name: "a\nb".into() }));
        assert!(ack_valid(&HistoryAck { transfer_id: vec![1; 16], next: 3, done: true }));
        assert!(!ack_valid(&HistoryAck { transfer_id: vec![], next: 0, done: false }));
        let c = HistoryChunk { transfer_id: vec![1; 16], index: 2, total: 2, items: vec![], groups: vec![] };
        assert!(!chunk_valid(&c), "index past the end");
        assert!(!chunk_valid(&HistoryChunk { total: MAX_CHUNKS + 1, index: 0, ..c.clone() }));
    }
}
