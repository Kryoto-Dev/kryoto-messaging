//! Chat rules every client applies the same way: conversation ids, message
//! limits, which GIF addresses may be loaded, and what a receiver does with a
//! message that breaks the rules.
//!
//! The server cannot read messages, so it cannot enforce any of this. The
//! sending client applies the limits; every receiving client applies them
//! again against what it knows about the sender (supporter or not), so a
//! modified client gains nothing by ignoring them.

use km_proto::{content::Body, Content};

use crate::error::{CoreError, Result};

/// Characters in a message (and an edit) for everyone...
pub const TEXT_LIMIT: usize = 2_000;
/// ...and for supporters.
pub const SUPPORTER_TEXT_LIMIT: usize = 8_000;
/// A reaction is one emoji; a few code points cover flags and skin tones.
pub const REACTION_LIMIT: usize = 16;
/// How long after sending a message can still be edited or deleted for everyone.
pub const EDIT_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

pub fn text_limit(supporter: bool) -> usize {
    if supporter {
        SUPPORTER_TEXT_LIMIT
    } else {
        TEXT_LIMIT
    }
}

/// The id of the 1:1 conversation between two accounts: the same on both
/// sides, whoever sends.
pub fn dm_conversation_id(a: u64, b: u64) -> Vec<u8> {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut id = Vec::with_capacity(19);
    id.extend_from_slice(b"dm:");
    id.extend_from_slice(&lo.to_be_bytes());
    id.extend_from_slice(&hi.to_be_bytes());
    id
}

/// The other account in a 1:1 conversation, if `me` is in it.
pub fn dm_peer(conversation_id: &[u8], me: u64) -> Option<u64> {
    if conversation_id.len() != 19 || &conversation_id[..3] != b"dm:" {
        return None;
    }
    let lo = u64::from_be_bytes(conversation_id[3..11].try_into().ok()?);
    let hi = u64::from_be_bytes(conversation_id[11..19].try_into().ok()?);
    match (lo == me, hi == me) {
        (true, _) => Some(hi),
        (_, true) => Some(lo),
        _ => None,
    }
}

/// A group conversation: "grp:" + the group id, big-endian.
pub fn group_conversation_id(group_id: u64) -> Vec<u8> {
    let mut id = Vec::with_capacity(12);
    id.extend_from_slice(b"grp:");
    id.extend_from_slice(&group_id.to_be_bytes());
    id
}

/// The group a conversation id names, if it is a group's.
pub fn group_of(conversation_id: &[u8]) -> Option<u64> {
    if conversation_id.len() != 12 || &conversation_id[..4] != b"grp:" {
        return None;
    }
    Some(u64::from_be_bytes(conversation_id[4..12].try_into().ok()?))
}

/// The longest group name.
pub const GROUP_NAME_LIMIT: usize = 64;

/// Media hosts each GIF provider serves from. Anything else is never loaded:
/// a message must not be able to make your app fetch an arbitrary address.
fn gif_host_allowed(provider: &str, host: &str) -> bool {
    let under = |root: &str| host == root || host.ends_with(&format!(".{root}"));
    match provider {
        "giphy" => under("giphy.com"),
        "klipy" => under("klipy.com"),
        _ => false,
    }
}

/// `https://<allowed host>/<path>` and nothing cleverer: no credentials, no
/// port, no other scheme.
pub fn gif_url_allowed(provider: &str, url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else { return false };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains(['@', ':']) || url.len() > 512 {
        return false;
    }
    gif_host_allowed(provider, &host.to_ascii_lowercase())
}

/// Check a message before sending it. `supporter` is the sender's own status.
pub fn validate_outgoing(content: &Content, supporter: bool) -> Result<()> {
    let limit = text_limit(supporter);
    let too_long = |s: &str| s.chars().count() > limit;
    match &content.body {
        Some(Body::Text(t)) => {
            if t.text.trim().is_empty() {
                return Err(CoreError::Malformed);
            }
            if too_long(&t.text) {
                return Err(CoreError::TooLarge);
            }
        }
        Some(Body::Edit(e)) => {
            if e.target.len() != 16 || e.text.trim().is_empty() {
                return Err(CoreError::Malformed);
            }
            if too_long(&e.text) {
                return Err(CoreError::TooLarge);
            }
        }
        Some(Body::Delete(d)) if d.target.len() != 16 => return Err(CoreError::Malformed),
        Some(Body::Reaction(r)) if r.target.len() != 16 || r.emoji.is_empty() || r.emoji.chars().count() > REACTION_LIMIT => {
            return Err(CoreError::Malformed)
        }
        Some(Body::Invite(i)) if !invite_valid(i) => return Err(CoreError::Malformed),
        Some(Body::Attachment(a)) if !attachment_valid(a) => return Err(CoreError::Malformed),
        Some(Body::Call(c)) if !call_valid(c) => return Err(CoreError::Malformed),
        Some(Body::CallLog(l)) if !call_log_valid(l) => return Err(CoreError::Malformed),
        Some(Body::GroupMeta(g)) if g.name.trim().is_empty() || g.name.chars().count() > GROUP_NAME_LIMIT => {
            return Err(CoreError::Malformed)
        }
        Some(Body::Gif(g)) => {
            // GIFs are a supporter perk.
            if !supporter {
                return Err(CoreError::Malformed);
            }
            if !gif_url_allowed(&g.provider, &g.url) {
                return Err(CoreError::Malformed);
            }
        }
        _ => {}
    }
    Ok(())
}

/// An invite a client may send or show: a real-looking slug, a short title,
/// and lobby/host ids that are plain decimal numbers (they end up on a
/// command line and in a steam:// link, so nothing else is allowed).
pub fn invite_valid(i: &km_proto::Invite) -> bool {
    let digits = |s: &str| s.is_empty() || (s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()));
    !i.slug.is_empty()
        && i.slug.len() <= 120
        && i.slug.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !i.title.trim().is_empty()
        && i.title.chars().count() <= 120
        && digits(&i.steam_lobby)
        && digits(&i.host_steam_id)
        && i.expires_at_ms > 0
}

/// An attachment a client may send or show: a real key and hash, a token
/// and name that are safe to use in a URL and a file name.
pub fn attachment_valid(a: &km_proto::Attachment) -> bool {
    a.id != 0
        && a.key.len() == 32
        && a.sha256.len() == 32
        && (16..=128).contains(&a.download_token.len())
        && a.download_token.bytes().all(|b| b.is_ascii_hexdigit())
        && !a.name.trim().is_empty()
        && a.name.chars().count() <= 200
        && !a.name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\'))
        && a.mime.len() <= 100
        && a.size <= crate::MAX_ATTACHMENT as u64
}

/// Call signalling within sane bounds (an SDP is a few KB).
pub fn call_valid(c: &km_proto::Call) -> bool {
    c.call_id.len() == 16 && km_proto::CallKind::try_from(c.kind).is_ok_and(|k| k != km_proto::CallKind::Unspecified) && c.payload.len() <= 16 * 1024
}

/// A call record: one call, and no call lasts more than a day.
pub fn call_log_valid(l: &km_proto::CallLog) -> bool {
    l.call_id.len() == 16 && (l.answered || l.seconds == 0) && l.seconds <= 24 * 3600
}

/// What a receiver shows for an incoming message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// Within the rules.
    Ok,
    /// Text cut to the sender's limit (they are not a supporter, or a client
    /// sent more than anyone may).
    Truncated(String),
    /// A GIF from a non-supporter, or from a host that is not the provider's:
    /// shown as plain text, never loaded.
    GifAsText(String),
}

/// Apply the rules on the receiving side. `sender_supporter` comes from the
/// sender's public profile, not from anything inside the message.
pub fn receive_rules(content: &Content, sender_supporter: bool) -> Shown {
    let limit = text_limit(sender_supporter);
    let cut = |s: &str| -> Option<String> {
        (s.chars().count() > limit).then(|| s.chars().take(limit).collect())
    };
    match &content.body {
        Some(Body::Text(t)) => cut(&t.text).map(Shown::Truncated).unwrap_or(Shown::Ok),
        Some(Body::Edit(e)) => cut(&e.text).map(Shown::Truncated).unwrap_or(Shown::Ok),
        Some(Body::Gif(g)) if !sender_supporter || !gif_url_allowed(&g.provider, &g.url) => {
            let label = if g.title.trim().is_empty() { "GIF".to_string() } else { format!("GIF: {}", g.title.trim()) };
            Shown::GifAsText(label.chars().take(200).collect())
        }
        _ => Shown::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use km_proto::{Gif, Reaction, Text};

    fn content(body: Body) -> Content {
        Content { msg_id: vec![1; 16], conversation_id: vec![], sent_at_ms: 0, body: Some(body) }
    }

    #[test]
    fn dm_ids_match_on_both_sides() {
        assert_eq!(dm_conversation_id(5, 9), dm_conversation_id(9, 5));
        assert_ne!(dm_conversation_id(5, 9), dm_conversation_id(5, 10));
        let id = dm_conversation_id(5, 9);
        assert_eq!(dm_peer(&id, 5), Some(9));
        assert_eq!(dm_peer(&id, 9), Some(5));
        assert_eq!(dm_peer(&id, 7), None, "not your conversation");
        assert_eq!(dm_peer(b"group:xyz", 5), None);
    }

    #[test]
    fn length_limits_depend_on_supporting() {
        let long = content(Body::Text(Text { text: "x".repeat(3000), reply_to: vec![] }));
        assert_eq!(validate_outgoing(&long, false), Err(CoreError::TooLarge));
        assert!(validate_outgoing(&long, true).is_ok());
        let huge = content(Body::Text(Text { text: "x".repeat(8001), reply_to: vec![] }));
        assert_eq!(validate_outgoing(&huge, true), Err(CoreError::TooLarge));
        // Characters, not bytes: 2000 emoji are fine.
        let emoji = content(Body::Text(Text { text: "😀".repeat(2000), reply_to: vec![] }));
        assert!(validate_outgoing(&emoji, false).is_ok());
    }

    #[test]
    fn receivers_cut_what_the_sender_may_not_send() {
        let long = content(Body::Text(Text { text: "y".repeat(3000), reply_to: vec![] }));
        assert_eq!(receive_rules(&long, true), Shown::Ok);
        match receive_rules(&long, false) {
            Shown::Truncated(t) => assert_eq!(t.chars().count(), TEXT_LIMIT),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn call_records_are_one_call_within_a_day() {
        let log = |call_id: Vec<u8>, answered: bool, seconds: u32| content(Body::CallLog(km_proto::CallLog { call_id, answered, seconds }));
        assert!(validate_outgoing(&log(vec![1; 16], true, 185), false).is_ok());
        assert!(validate_outgoing(&log(vec![1; 16], false, 0), false).is_ok(), "a missed call");
        assert!(validate_outgoing(&log(vec![1; 16], false, 30), false).is_err(), "unanswered calls have no length");
        assert!(validate_outgoing(&log(vec![1; 15], true, 1), false).is_err());
        assert!(validate_outgoing(&log(vec![1; 16], true, 2 * 24 * 3600), false).is_err());
        assert!(validate_outgoing(&content(Body::Active(km_proto::Active {})), false).is_ok());
    }

    #[test]
    fn group_conversation_ids_round_trip_and_never_look_like_dms() {
        let id = group_conversation_id(987_654_321);
        assert_eq!(group_of(&id), Some(987_654_321));
        assert_eq!(dm_peer(&id, 987_654_321), None);
        assert_eq!(group_of(&dm_conversation_id(1, 2)), None);
        assert!(validate_outgoing(&content(Body::GroupMeta(km_proto::GroupMeta { name: "Lethal crew".into() })), false).is_ok());
        assert!(validate_outgoing(&content(Body::GroupMeta(km_proto::GroupMeta { name: " ".into() })), false).is_err());
        assert!(validate_outgoing(&content(Body::GroupMeta(km_proto::GroupMeta { name: "x".repeat(65) })), false).is_err());
    }

    #[test]
    fn invites_carry_only_safe_values() {
        let ok = km_proto::Invite {
            slug: "lethal-company".into(),
            title: "Lethal Company".into(),
            steam_lobby: "109775241075364289".into(),
            host_steam_id: "76561198000000000".into(),
            expires_at_ms: 1,
        };
        assert!(invite_valid(&ok));
        assert!(validate_outgoing(&content(Body::Invite(ok.clone())), false).is_ok(), "anyone may invite");
        for bad in [
            km_proto::Invite { slug: "../x".into(), ..ok.clone() },
            km_proto::Invite { steam_lobby: "1 -exec".into(), ..ok.clone() },
            km_proto::Invite { host_steam_id: "abc".into(), ..ok.clone() },
            km_proto::Invite { title: " ".into(), ..ok.clone() },
            km_proto::Invite { expires_at_ms: 0, ..ok.clone() },
        ] {
            assert!(!invite_valid(&bad), "{bad:?}");
            assert!(validate_outgoing(&content(Body::Invite(bad)), true).is_err());
        }
    }

    #[test]
    fn gifs_are_for_supporters_and_only_from_the_provider() {
        let gif = |url: &str| {
            content(Body::Gif(Gif {
                provider: "giphy".into(),
                id: "abc".into(),
                url: url.into(),
                width: 200,
                height: 200,
                title: "cat".into(),
            }))
        };
        let good = gif("https://media2.giphy.com/media/abc/giphy.webp");
        assert!(validate_outgoing(&good, true).is_ok());
        assert!(validate_outgoing(&good, false).is_err(), "not a supporter");
        assert_eq!(receive_rules(&good, true), Shown::Ok);
        assert_eq!(receive_rules(&good, false), Shown::GifAsText("GIF: cat".into()));
        for bad in [
            "http://media.giphy.com/x.gif",
            "https://evil.example/x.gif",
            "https://giphy.com.evil.example/x.gif",
            "https://user@media.giphy.com/x.gif",
            "https://media.giphy.com:8443/x.gif",
            "javascript:alert(1)",
        ] {
            assert!(!gif_url_allowed("giphy", bad), "{bad}");
            assert!(matches!(receive_rules(&gif(bad), true), Shown::GifAsText(_)), "{bad}");
        }
        assert!(gif_url_allowed("klipy", "https://static.klipy.com/a.gif"));
        assert!(!gif_url_allowed("tenor", "https://media.tenor.com/a.gif"));
    }

    #[test]
    fn reactions_are_small() {
        let r = |e: &str| content(Body::Reaction(Reaction { target: vec![2; 16], emoji: e.into(), remove: false }));
        assert!(validate_outgoing(&r("🔥"), false).is_ok());
        assert!(validate_outgoing(&r(""), false).is_err());
        assert!(validate_outgoing(&r(&"a".repeat(17)), false).is_err());
    }
}
