//! Conversations and messages, in the same encrypted database as the keys.
//!
//! Plaintext lives here and nowhere else: this file is the only place a
//! message is ever written down, and the whole database is SQLCipher.

use km_core::chat::dm_peer;
use km_core::history;
use km_core::proto::{HistoryItem, HistoryReaction};
use rusqlite::{params, OptionalExtension, Row};
use serde::Serialize;

use crate::{Result, Store};

/// Where an outgoing message has got to. Only ever moves forward
/// (`Failed` is the exception: a send that gave up, which a retry replaces).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Sending,
    Sent,
    Delivered,
    Read,
    Failed,
    /// An incoming message.
    Received,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Sending => "sending",
            Status::Sent => "sent",
            Status::Delivered => "delivered",
            Status::Read => "read",
            Status::Failed => "failed",
            Status::Received => "received",
        }
    }

    fn parse(s: &str) -> Status {
        match s {
            "sending" => Status::Sending,
            "sent" => Status::Sent,
            "delivered" => Status::Delivered,
            "read" => Status::Read,
            "failed" => Status::Failed,
            _ => Status::Received,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Status::Failed => 0,
            Status::Sending => 1,
            Status::Sent => 2,
            Status::Delivered => 3,
            Status::Read => 4,
            Status::Received => 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReactionRow {
    pub emoji: String,
    pub user_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRow {
    /// Hex of the 16-byte message id.
    pub msg_id: String,
    /// Hex of the conversation id.
    pub conversation_id: String,
    pub sender_user: String,
    #[serde(skip)]
    pub sender_device: u64,
    pub outgoing: bool,
    pub sent_at: u64,
    pub received_at: u64,
    /// "text" or "gif" (body is then the GIF as JSON).
    pub kind: String,
    pub body: String,
    pub reply_to: Option<String>,
    pub edited_at: Option<u64>,
    pub deleted: bool,
    pub status: Status,
    pub reactions: Vec<ReactionRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConversationRow {
    pub id: String,
    pub peer_user_id: Option<String>,
    pub last_at: u64,
    pub unread: u64,
    /// The newest message, for the list.
    pub last: Option<MessageRow>,
}

const MSG_COLS: &str = "msg_id, conversation_id, sender_user, sender_device, outgoing, sent_at, received_at, \
                        kind, body, reply_to, edited_at, deleted, status";

fn message_from(r: &Row<'_>) -> rusqlite::Result<MessageRow> {
    let msg_id: Vec<u8> = r.get(0)?;
    let conv: Vec<u8> = r.get(1)?;
    let reply: Option<Vec<u8>> = r.get(9)?;
    let status: String = r.get(12)?;
    Ok(MessageRow {
        msg_id: hex::encode(msg_id),
        conversation_id: hex::encode(conv),
        sender_user: r.get::<_, i64>(2)?.to_string(),
        sender_device: r.get::<_, i64>(3)? as u64,
        outgoing: r.get::<_, i64>(4)? != 0,
        sent_at: r.get::<_, i64>(5)? as u64,
        received_at: r.get::<_, i64>(6)? as u64,
        kind: r.get(7)?,
        body: r.get(8)?,
        reply_to: reply.map(hex::encode),
        edited_at: r.get::<_, Option<i64>>(10)?.map(|v| v as u64),
        deleted: r.get::<_, i64>(11)? != 0,
        status: Status::parse(&status),
        reactions: Vec::new(),
    })
}

/// A stored row as it travels (km-core `history`).
pub fn item_of(m: &MessageRow) -> HistoryItem {
    HistoryItem {
        msg_id: hex::decode(&m.msg_id).unwrap_or_default(),
        conversation_id: hex::decode(&m.conversation_id).unwrap_or_default(),
        sender_user: m.sender_user.parse().unwrap_or(0),
        sender_device: m.sender_device,
        outgoing: m.outgoing,
        sent_at_ms: m.sent_at,
        received_at_ms: m.received_at,
        kind: m.kind.clone(),
        body: m.body.clone(),
        reply_to: m.reply_to.as_deref().and_then(|r| hex::decode(r).ok()).unwrap_or_default(),
        edited_at_ms: m.edited_at.unwrap_or(0),
        deleted: m.deleted,
        status: m.status.as_str().into(),
        reactions: m
            .reactions
            .iter()
            .map(|r| HistoryReaction { emoji: r.emoji.clone(), user_ids: r.user_ids.iter().filter_map(|u| u.parse().ok()).collect() })
            .collect(),
    }
}

/// A new message to store.
pub struct NewMessage<'a> {
    pub msg_id: &'a [u8],
    pub conversation_id: &'a [u8],
    pub peer_user_id: Option<u64>,
    pub sender_user: u64,
    pub sender_device: u64,
    pub outgoing: bool,
    pub sent_at: u64,
    pub received_at: u64,
    pub kind: &'a str,
    pub body: &'a str,
    pub reply_to: Option<&'a [u8]>,
    pub status: Status,
}

impl Store {
    /// Store a message (and its conversation). False if it was already there.
    pub fn insert_message(&self, m: &NewMessage<'_>) -> Result<bool> {
        let c = self.conn();
        c.execute(
            "INSERT INTO conversations (id, peer_user_id, last_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (id) DO UPDATE SET last_at = max(last_at, excluded.last_at)",
            params![m.conversation_id, m.peer_user_id.map(|v| v as i64), m.sent_at as i64],
        )?;
        let n = c.execute(
            "INSERT INTO messages (msg_id, conversation_id, sender_user, sender_device, outgoing, sent_at,
                                   received_at, kind, body, reply_to, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT (msg_id) DO NOTHING",
            params![
                m.msg_id,
                m.conversation_id,
                m.sender_user as i64,
                m.sender_device as i64,
                i64::from(m.outgoing),
                m.sent_at as i64,
                m.received_at as i64,
                m.kind,
                m.body,
                m.reply_to,
                m.status.as_str(),
            ],
        )?;
        if n > 0 && !m.outgoing {
            c.execute("UPDATE conversations SET unread = unread + 1 WHERE id = ?1", params![m.conversation_id])?;
        }
        Ok(n > 0)
    }

    pub fn message(&self, msg_id: &[u8]) -> Result<Option<MessageRow>> {
        let row = self
            .conn()
            .query_row(&format!("SELECT {MSG_COLS} FROM messages WHERE msg_id = ?1"), params![msg_id], message_from)
            .optional()?;
        Ok(match row {
            Some(mut m) => {
                m.reactions = self.reactions_for(msg_id)?;
                Some(m)
            }
            None => None,
        })
    }

    /// Up to `limit` messages before a point (oldest first in the result).
    pub fn messages(&self, conversation_id: &[u8], before: Option<u64>, limit: u32) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {MSG_COLS} FROM messages
              WHERE conversation_id = ?1 AND sent_at < ?2
              ORDER BY sent_at DESC, msg_id DESC LIMIT ?3"
        ))?;
        let mut rows = stmt
            .query_map(params![conversation_id, before.map(|b| b as i64).unwrap_or(i64::MAX), limit], message_from)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.reverse();
        for m in &mut rows {
            m.reactions = self.reactions_for(&hex::decode(&m.msg_id).unwrap_or_default())?;
        }
        Ok(rows)
    }

    pub fn conversations(&self) -> Result<Vec<ConversationRow>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT id, peer_user_id, last_at, unread FROM conversations ORDER BY last_at DESC")?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(id, peer, last_at, unread)| {
                Ok(ConversationRow {
                    last: self.messages(&id, None, 1)?.pop(),
                    id: hex::encode(&id),
                    peer_user_id: peer.map(|p| p.to_string()),
                    last_at: last_at as u64,
                    unread: unread as u64,
                })
            })
            .collect()
    }

    /// Move an outgoing message's status forward (never back).
    pub fn advance_status(&self, msg_id: &[u8], status: Status) -> Result<bool> {
        let current: Option<String> = self
            .conn()
            .query_row("SELECT status FROM messages WHERE msg_id = ?1 AND outgoing = 1", params![msg_id], |r| r.get(0))
            .optional()?;
        let Some(current) = current else { return Ok(false) };
        let current = Status::parse(&current);
        let forward = status.rank() > current.rank() || (status == Status::Failed && current == Status::Sending);
        if !forward {
            return Ok(false);
        }
        self.conn().execute("UPDATE messages SET status = ?2 WHERE msg_id = ?1", params![msg_id, status.as_str()])?;
        Ok(true)
    }

    /// Apply an edit, if `sender_user` wrote the message and it still exists.
    pub fn apply_edit(&self, msg_id: &[u8], sender_user: u64, text: &str, at: u64) -> Result<bool> {
        let n = self.conn().execute(
            "UPDATE messages SET body = ?3, edited_at = ?4
              WHERE msg_id = ?1 AND sender_user = ?2 AND deleted = 0 AND kind = 'text'",
            params![msg_id, sender_user as i64, text, at as i64],
        )?;
        Ok(n > 0)
    }

    /// Delete for everyone, if `sender_user` wrote it. The text is erased.
    pub fn apply_delete(&self, msg_id: &[u8], sender_user: u64) -> Result<bool> {
        let n = self.conn().execute(
            "UPDATE messages SET deleted = 1, body = '' WHERE msg_id = ?1 AND sender_user = ?2 AND deleted = 0",
            params![msg_id, sender_user as i64],
        )?;
        if n > 0 {
            self.conn().execute("DELETE FROM reactions WHERE msg_id = ?1", params![msg_id])?;
        }
        Ok(n > 0)
    }

    pub fn apply_reaction(&self, msg_id: &[u8], user_id: u64, emoji: &str, remove: bool) -> Result<bool> {
        let exists: bool = self
            .conn()
            .query_row("SELECT 1 FROM messages WHERE msg_id = ?1 AND deleted = 0", params![msg_id], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !exists {
            return Ok(false);
        }
        let n = if remove {
            self.conn().execute(
                "DELETE FROM reactions WHERE msg_id = ?1 AND user_id = ?2 AND emoji = ?3",
                params![msg_id, user_id as i64, emoji],
            )?
        } else {
            self.conn().execute(
                "INSERT INTO reactions (msg_id, user_id, emoji) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                params![msg_id, user_id as i64, emoji],
            )?
        };
        Ok(n > 0)
    }

    fn reactions_for(&self, msg_id: &[u8]) -> Result<Vec<ReactionRow>> {
        let mut stmt = self
            .conn()
            .prepare("SELECT emoji, user_id FROM reactions WHERE msg_id = ?1 ORDER BY emoji, user_id")?;
        let pairs = stmt
            .query_map(params![msg_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut out: Vec<ReactionRow> = Vec::new();
        for (emoji, user) in pairs {
            match out.last_mut() {
                Some(last) if last.emoji == emoji => last.user_ids.push(user.to_string()),
                _ => out.push(ReactionRow { emoji, user_ids: vec![user.to_string()] }),
            }
        }
        Ok(out)
    }

    /// Mark a conversation read; returns the ids of incoming messages that
    /// had not been read yet (for read receipts).
    pub fn mark_read(&self, conversation_id: &[u8], up_to: u64) -> Result<Vec<Vec<u8>>> {
        let mut stmt = self.conn().prepare(
            "SELECT msg_id FROM messages
              WHERE conversation_id = ?1 AND outgoing = 0 AND status = 'received' AND sent_at <= ?2 AND deleted = 0",
        )?;
        let ids = stmt
            .query_map(params![conversation_id, up_to as i64], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        // Incoming messages keep `received`; reading is tracked by the counter
        // and by which receipts were sent (`read` on an incoming row).
        for id in &ids {
            self.conn().execute("UPDATE messages SET status = 'read' WHERE msg_id = ?1", params![id])?;
        }
        self.conn().execute("UPDATE conversations SET unread = 0 WHERE id = ?1", params![conversation_id])?;
        Ok(ids)
    }

    /// Outgoing messages that never reached the server (sent while offline,
    /// or the app closed mid-send), oldest first, to send again.
    pub fn pending_outgoing(&self) -> Result<Vec<MessageRow>> {
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {MSG_COLS} FROM messages WHERE outgoing = 1 AND status = 'sending' AND deleted = 0 ORDER BY sent_at"
        ))?;
        let rows = stmt.query_map([], message_from)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every stored message as it travels to another of the account's
    /// devices (km-core `history`), oldest first. Which of them may travel is
    /// km-core's call.
    pub fn history_items(&self) -> Result<Vec<HistoryItem>> {
        let mut stmt = self.conn().prepare(&format!("SELECT {MSG_COLS} FROM messages ORDER BY sent_at, msg_id"))?;
        let rows = stmt.query_map([], message_from)?.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        rows.into_iter()
            .map(|mut m| {
                m.reactions = self.reactions_for(&hex::decode(&m.msg_id).unwrap_or_default())?;
                Ok(item_of(&m))
            })
            .collect()
    }

    /// Take in history from another of the account's devices: new rows are
    /// stored, known ones completed (km-core `history::merge`), each once.
    /// Unread counts follow the rows. Returns how many rows were written.
    pub fn merge_history(&self, me: u64, items: Vec<HistoryItem>) -> Result<usize> {
        let rows = history::merge_rows(me, items, |id| self.message(id).ok().flatten().map(|m| item_of(&m)));
        if rows.is_empty() {
            return Ok(0);
        }
        let tx = self.conn().unchecked_transaction()?;
        let mut touched = std::collections::BTreeSet::new();
        for r in &rows {
            tx.execute(
                "INSERT INTO conversations (id, peer_user_id, last_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT (id) DO UPDATE SET last_at = max(last_at, excluded.last_at)",
                params![r.conversation_id, dm_peer(&r.conversation_id, me).map(|v| v as i64), r.sent_at_ms as i64],
            )?;
            tx.execute(
                "INSERT INTO messages (msg_id, conversation_id, sender_user, sender_device, outgoing, sent_at,
                                       received_at, kind, body, reply_to, edited_at, deleted, status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
                 ON CONFLICT (msg_id) DO UPDATE SET body = excluded.body, edited_at = excluded.edited_at,
                                                    deleted = excluded.deleted, status = excluded.status",
                params![
                    r.msg_id,
                    r.conversation_id,
                    r.sender_user as i64,
                    r.sender_device as i64,
                    i64::from(r.outgoing),
                    r.sent_at_ms as i64,
                    r.received_at_ms as i64,
                    r.kind,
                    r.body,
                    (!r.reply_to.is_empty()).then_some(&r.reply_to),
                    (r.edited_at_ms != 0).then_some(r.edited_at_ms as i64),
                    i64::from(r.deleted),
                    r.status,
                ],
            )?;
            tx.execute("DELETE FROM reactions WHERE msg_id = ?1", params![r.msg_id])?;
            for re in &r.reactions {
                for u in &re.user_ids {
                    tx.execute(
                        "INSERT INTO reactions (msg_id, user_id, emoji) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
                        params![r.msg_id, *u as i64, re.emoji],
                    )?;
                }
            }
            touched.insert(r.conversation_id.clone());
        }
        for conv in touched {
            tx.execute(
                "UPDATE conversations SET unread = (SELECT count(*) FROM messages
                   WHERE conversation_id = ?1 AND outgoing = 0 AND status = 'received' AND deleted = 0)
                 WHERE id = ?1",
                params![conv],
            )?;
        }
        tx.commit()?;
        Ok(rows.len())
    }

    /// Messages containing `query` (case-insensitive), newest first. Local
    /// only: nothing is ever searched on a server.
    pub fn search(&self, query: &str, limit: u32) -> Result<Vec<MessageRow>> {
        let pattern = format!("%{}%", query.replace(['%', '_'], ""));
        let mut stmt = self.conn().prepare(&format!(
            "SELECT {MSG_COLS} FROM messages
              WHERE deleted = 0 AND kind = 'text' AND body LIKE ?1
              ORDER BY sent_at DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![pattern, limit], message_from)?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}
