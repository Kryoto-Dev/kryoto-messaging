//! Kryoto chat in the browser.
//!
//! The web client (chat.kryo.to) runs this as WebAssembly. Everything secret
//! stays inside: the device's Olm account and sessions, the master key and
//! the trust pins live in a [`Kryo`] object, and JavaScript only ever handles
//! encrypted frames, public keys and the plaintext it has to display. The
//! gateway protocol (protobuf) is encoded and decoded here too, so the page
//! never has to know its wire format.
//!
//! Persistence: [`Kryo::state`] returns everything needed to restore the
//! object later, secrets included. The page encrypts it with a non-extractable
//! WebCrypto key before it touches IndexedDB.
//!
//! Binary values go in and out as `Uint8Array` where they are the point of a
//! call (envelopes, frames, files), and as base64 or hex inside JSON
//! otherwise.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use km_core::chat::{receive_rules, validate_outgoing, Shown};
use km_core::{
    display_groups, new_message_id, open_attachment, open_backup, safety_number, seal_attachment, seal_backup, CoreError, DeviceKeys,
    DeviceKind, LocalDevice, MasterKey, RecoveryKey, SignedDevice, SignedPrekey, TrustLevel, TrustStore, TrustedDevice, UserDevices,
};
use km_proto::gateway::{self as gw, client_frame::Kind as C, server_frame::Kind as S, ClientFrame, ServerFrame};
use km_proto::{content::Body, Content};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn err(m: impl std::fmt::Display) -> JsError {
    JsError::new(&m.to_string())
}

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

fn unb64(v: &Value) -> Result<Vec<u8>, JsError> {
    B64.decode(v.as_str().unwrap_or_default()).map_err(|_| err("bad base64"))
}

fn unhex(v: &Value) -> Result<Vec<u8>, JsError> {
    hex::decode(v.as_str().unwrap_or_default()).map_err(|_| err("bad hex"))
}

fn num(v: &Value) -> Result<u64, JsError> {
    match v {
        Value::String(s) => s.parse().map_err(|_| err("bad number")),
        Value::Number(n) => n.as_u64().ok_or_else(|| err("bad number")),
        _ => Err(err("missing number")),
    }
}

fn arr32(b: &[u8]) -> Result<[u8; 32], JsError> {
    b.try_into().map_err(|_| err("expected 32 bytes"))
}

// ---- content <-> JSON -----------------------------------------------------------

fn content_to_json(c: &Content) -> Value {
    let body = match &c.body {
        Some(Body::Text(t)) => json!({ "type": "text", "text": t.text, "replyTo": hex::encode(&t.reply_to) }),
        Some(Body::Receipt(r)) => json!({
            "type": "receipt",
            "receiptKind": if r.kind == km_proto::ReceiptKind::Read as i32 { "read" } else { "delivered" },
            "msgIds": r.msg_ids.iter().map(hex::encode).collect::<Vec<_>>(),
        }),
        Some(Body::Typing(t)) => json!({ "type": "typing", "active": t.active }),
        Some(Body::Edit(e)) => json!({ "type": "edit", "target": hex::encode(&e.target), "text": e.text }),
        Some(Body::Delete(d)) => json!({ "type": "delete", "target": hex::encode(&d.target) }),
        Some(Body::Reaction(r)) => json!({ "type": "reaction", "target": hex::encode(&r.target), "emoji": r.emoji, "remove": r.remove }),
        Some(Body::Gif(g)) => json!({ "type": "gif", "provider": g.provider, "id": g.id, "url": g.url, "width": g.width, "height": g.height, "title": g.title }),
        Some(Body::Invite(i)) => json!({
            "type": "invite", "slug": i.slug, "title": i.title, "steamLobby": i.steam_lobby, "hostSteamId": i.host_steam_id, "expiresAt": i.expires_at_ms,
        }),
        Some(Body::GroupMeta(g)) => json!({ "type": "groupMeta", "name": g.name }),
        Some(Body::Attachment(a)) => json!({
            "type": "file", "id": a.id.to_string(), "token": a.download_token, "key": hex::encode(&a.key), "sha256": hex::encode(&a.sha256),
            "name": a.name, "mime": a.mime, "size": a.size, "width": a.width, "height": a.height,
        }),
        Some(Body::Call(k)) => json!({
            "type": "call",
            "callId": hex::encode(&k.call_id),
            "callKind": match km_proto::CallKind::try_from(k.kind) {
                Ok(km_proto::CallKind::Offer) => "offer",
                Ok(km_proto::CallKind::Answer) => "answer",
                Ok(km_proto::CallKind::Ice) => "ice",
                Ok(km_proto::CallKind::Hangup) => "hangup",
                Ok(km_proto::CallKind::Decline) => "decline",
                Ok(km_proto::CallKind::Busy) => "busy",
                Ok(km_proto::CallKind::Restart) => "restart",
                Ok(km_proto::CallKind::Restarted) => "restarted",
                Ok(km_proto::CallKind::Muted) => "muted",
                Ok(km_proto::CallKind::Unmuted) => "unmuted",
                _ => "unknown",
            },
            "payload": k.payload,
        }),
        None => json!({ "type": "none" }),
    };
    json!({ "msgId": hex::encode(&c.msg_id), "conversationId": hex::encode(&c.conversation_id), "sentAt": c.sent_at_ms, "body": body })
}

fn content_from_json(v: &Value) -> Result<Content, JsError> {
    let b = &v["body"];
    let s = |k: &str| b[k].as_str().unwrap_or_default().to_string();
    let body = match b["type"].as_str().unwrap_or_default() {
        "text" => Body::Text(km_proto::Text { text: s("text"), reply_to: unhex(&b["replyTo"]).unwrap_or_default() }),
        "receipt" => Body::Receipt(km_proto::Receipt {
            kind: if b["receiptKind"] == "read" { km_proto::ReceiptKind::Read } else { km_proto::ReceiptKind::Delivered } as i32,
            msg_ids: b["msgIds"].as_array().into_iter().flatten().filter_map(|x| hex::decode(x.as_str()?).ok()).collect(),
        }),
        "typing" => Body::Typing(km_proto::Typing { active: b["active"].as_bool().unwrap_or(false) }),
        "edit" => Body::Edit(km_proto::Edit { target: unhex(&b["target"])?, text: s("text") }),
        "delete" => Body::Delete(km_proto::Delete { target: unhex(&b["target"])? }),
        "reaction" => Body::Reaction(km_proto::Reaction { target: unhex(&b["target"])?, emoji: s("emoji"), remove: b["remove"].as_bool().unwrap_or(false) }),
        "gif" => Body::Gif(km_proto::Gif {
            provider: s("provider"),
            id: s("id"),
            url: s("url"),
            width: b["width"].as_u64().unwrap_or(0) as u32,
            height: b["height"].as_u64().unwrap_or(0) as u32,
            title: s("title"),
        }),
        "invite" => Body::Invite(km_proto::Invite {
            slug: s("slug"),
            title: s("title"),
            steam_lobby: s("steamLobby"),
            host_steam_id: s("hostSteamId"),
            expires_at_ms: b["expiresAt"].as_u64().unwrap_or(0),
        }),
        "groupMeta" => Body::GroupMeta(km_proto::GroupMeta { name: s("name") }),
        "file" => Body::Attachment(km_proto::Attachment {
            id: num(&b["id"])?,
            download_token: s("token"),
            key: unhex(&b["key"])?,
            sha256: unhex(&b["sha256"])?,
            name: s("name"),
            mime: s("mime"),
            size: b["size"].as_u64().unwrap_or(0),
            width: b["width"].as_u64().unwrap_or(0) as u32,
            height: b["height"].as_u64().unwrap_or(0) as u32,
        }),
        "call" => Body::Call(km_proto::Call {
            call_id: unhex(&b["callId"])?,
            kind: match b["callKind"].as_str().unwrap_or_default() {
                "offer" => km_proto::CallKind::Offer,
                "answer" => km_proto::CallKind::Answer,
                "ice" => km_proto::CallKind::Ice,
                "hangup" => km_proto::CallKind::Hangup,
                "decline" => km_proto::CallKind::Decline,
                "busy" => km_proto::CallKind::Busy,
                "restart" => km_proto::CallKind::Restart,
                "restarted" => km_proto::CallKind::Restarted,
                "muted" => km_proto::CallKind::Muted,
                "unmuted" => km_proto::CallKind::Unmuted,
                _ => return Err(err("unknown call kind")),
            } as i32,
            payload: s("payload"),
        }),
        other => return Err(err(format!("unknown body type {other}"))),
    };
    Ok(Content {
        msg_id: unhex(&v["msgId"])?,
        conversation_id: unhex(&v["conversationId"])?,
        sent_at_ms: v["sentAt"].as_u64().unwrap_or(0),
        body: Some(body),
    })
}

// ---- server frames -> JSON ----------------------------------------------------

fn devices_json(d: &gw::Devices) -> Value {
    json!({ "users": d.users.iter().map(|u| json!({
        "userId": u.user_id.to_string(),
        "masterKey": b64(&u.master_key),
        "devices": u.devices.iter().map(|x| json!({
            "deviceId": x.device_id.to_string(), "kind": x.kind, "ed25519": b64(&x.ed25519), "curve25519": b64(&x.curve25519),
            "sealKey": b64(&x.seal_key), "mskSignature": b64(&x.msk_signature),
        })).collect::<Vec<_>>(),
    })).collect::<Vec<_>>() })
}

fn group_json(g: &gw::GroupInfo) -> Value {
    json!({
        "groupId": g.group_id.to_string(),
        "version": g.version,
        "members": g.members.iter().map(|m| json!({ "userId": m.user_id.to_string(), "role": m.role })).collect::<Vec<_>>(),
    })
}

fn server_to_json(f: &ServerFrame) -> Value {
    let rid = f.request_id;
    let (kind, v) = match &f.kind {
        Some(S::Challenge(c)) => ("challenge", json!({ "nonce": b64(&c.nonce) })),
        Some(S::Registered(r)) => ("registered", json!({ "deviceId": r.device_id.to_string() })),
        Some(S::Ready(r)) => ("ready", json!({
            "userId": r.user_id.to_string(), "deviceId": r.device_id.to_string(), "oneTimeKeys": r.one_time_keys,
            "hasFallbackKey": r.has_fallback_key, "certified": r.certified, "masterKey": hex::encode(&r.master_key),
            "pushKey": hex::encode(&r.push_public_key),
        })),
        Some(S::Error(e)) => ("error", json!({ "code": e.code, "message": e.message })),
        Some(S::Ok(_)) => ("ok", json!({})),
        Some(S::KeysCount(k)) => ("keysCount", json!({ "oneTimeKeys": k.one_time_keys, "hasFallbackKey": k.has_fallback_key })),
        Some(S::Devices(d)) => ("devices", devices_json(d)),
        Some(S::KeysBundle(b)) => ("keysBundle", json!({
            "userId": b.user_id.to_string(),
            "keys": b.keys.iter().map(|k| json!({
                "deviceId": k.device_id.to_string(),
                "prekey": k.prekey.as_ref().map(|p| json!({ "keyId": p.key_id, "key": b64(&p.key), "fallback": p.fallback, "signature": b64(&p.signature) })),
            })).collect::<Vec<_>>(),
        })),
        Some(S::SendAck(a)) => ("sendAck", json!({
            "status": match gw::SendStatus::try_from(a.status) {
                Ok(gw::SendStatus::Accepted) => "accepted",
                Ok(gw::SendStatus::DeviceMismatch) => "deviceMismatch",
                Ok(gw::SendStatus::Forbidden) => "forbidden",
                Ok(gw::SendStatus::RateLimited) => "rateLimited",
                _ => "unknown",
            },
        })),
        Some(S::Deliver(d)) => ("deliver", json!({ "seq": d.seq.to_string(), "envelope": b64(&d.envelope) })),
        Some(S::Event(e)) => ("event", json!({
            "event": match gw::EventKind::try_from(e.kind) {
                Ok(gw::EventKind::DevicesChanged) => "devicesChanged",
                Ok(gw::EventKind::MasterKeyChanged) => "masterKeyChanged",
                Ok(gw::EventKind::GroupChanged) => "groupChanged",
                _ => "unknown",
            },
            "userId": e.user_id.to_string(),
            "groupId": e.group_id.to_string(),
        })),
        Some(S::Backup(b)) => ("backup", json!({ "blob": b64(&b.blob), "updatedAt": b.updated_at_ms })),
        Some(S::DeviceList(l)) => ("deviceList", json!({ "devices": l.devices.iter().map(|d| json!({
            "deviceId": d.device_id.to_string(), "kind": if d.kind == 2 { "web" } else { "desktop" }, "name": d.name,
            "certified": d.certified, "createdAtMs": d.created_at_ms, "lastSeenDayMs": d.last_seen_day_ms,
        })).collect::<Vec<_>>() })),
        Some(S::Group(g)) => ("group", group_json(g)),
        Some(S::Groups(g)) => ("groups", json!({ "groups": g.groups.iter().map(group_json).collect::<Vec<_>>() })),
        Some(S::AttachmentUpload(a)) => ("attachmentUpload", json!({
            "id": a.id.to_string(), "uploadToken": a.upload_token, "downloadToken": a.download_token, "expiresAtMs": a.expires_at_ms,
        })),
        None => ("empty", json!({})),
    };
    let mut v = v;
    v["requestId"] = json!(rid);
    v["type"] = json!(kind);
    v
}

fn user_devices_from_json(u: &Value) -> Result<UserDevices, JsError> {
    let user_id = num(&u["userId"])?;
    let mut devices = Vec::new();
    for d in u["devices"].as_array().into_iter().flatten() {
        devices.push(SignedDevice {
            keys: DeviceKeys {
                user_id,
                device_id: num(&d["deviceId"])?,
                kind: if d["kind"].as_u64() == Some(2) { DeviceKind::Web } else { DeviceKind::Desktop },
                ed25519: arr32(&unb64(&d["ed25519"])?)?,
                curve25519: arr32(&unb64(&d["curve25519"])?)?,
                seal_key: arr32(&unb64(&d["sealKey"])?)?,
            },
            msk_signature: unb64(&d["mskSignature"])?.as_slice().try_into().map_err(|_| err("bad signature"))?,
        });
    }
    Ok(UserDevices { user_id, master_key: arr32(&unb64(&u["masterKey"])?)?, devices })
}

// ---- the device -------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct State {
    device: String,
    master: String,
    trust: TrustStore,
}

impl Drop for State {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.device);
        zeroize::Zeroize::zeroize(&mut self.master);
    }
}

/// This browser as a chat device: its keys, sessions and trust pins.
#[wasm_bindgen]
pub struct Kryo {
    device: LocalDevice,
    master: MasterKey,
    trust: TrustStore,
    /// Each user's checked devices.
    devices: HashMap<u64, Vec<TrustedDevice>>,
    /// Claimed prekeys, by device id, until a session is made with them.
    claims: HashMap<u64, SignedPrekey>,
}

fn frame(request_id: u32, kind: C) -> Vec<u8> {
    ClientFrame { request_id, kind: Some(kind) }.encode_to_vec()
}

fn ids(v: &Value) -> Result<Vec<u64>, JsError> {
    v.as_array().into_iter().flatten().map(num).collect()
}

#[wasm_bindgen]
impl Kryo {
    /// A brand-new web device for an account, with a fresh identity (used
    /// unless an existing identity is restored from a backup).
    pub fn create(user_id: &str) -> Result<Kryo, JsError> {
        let user_id: u64 = user_id.parse().map_err(|_| err("bad user id"))?;
        let master = MasterKey::generate();
        let mut trust = TrustStore::new();
        trust.pin_own(user_id, master.public_key());
        Ok(Kryo { device: LocalDevice::new(user_id, DeviceKind::Web), master, trust, devices: HashMap::new(), claims: HashMap::new() })
    }

    pub fn restore(state: &str) -> Result<Kryo, JsError> {
        let s: State = serde_json::from_str(state).map_err(|_| err("damaged state"))?;
        let device = LocalDevice::restore(&s.device).map_err(err)?;
        let mut secret = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(&s.master, secret.as_mut_slice()).map_err(|_| err("damaged state"))?;
        Ok(Kryo { device, master: MasterKey::from_secret_bytes(&secret), trust: s.trust.clone(), devices: HashMap::new(), claims: HashMap::new() })
    }

    /// Everything needed to restore this device. Secret: encrypt before storing.
    pub fn state(&self) -> Result<String, JsError> {
        let s = State {
            device: self.device.snapshot().map_err(err)?.to_string(),
            master: hex::encode(self.master.to_secret_bytes().as_slice()),
            trust: self.trust.clone(),
        };
        serde_json::to_string(&s).map_err(err)
    }

    #[wasm_bindgen(js_name = userId)]
    pub fn user_id(&self) -> String {
        self.device.user_id().to_string()
    }

    #[wasm_bindgen(js_name = deviceId)]
    pub fn device_id(&self) -> Option<String> {
        self.device.device_id().map(|d| d.to_string())
    }

    #[wasm_bindgen(js_name = masterPublic)]
    pub fn master_public(&self) -> String {
        hex::encode(self.master.public_key())
    }

    // ---- handshake ----

    pub fn hello(&self, token: &str) -> Vec<u8> {
        frame(0, C::Hello(gw::Hello { token: token.into(), protocol_version: gw::PROTOCOL_VERSION, device_id: self.device.device_id().unwrap_or(0) }))
    }

    pub fn proof(&self, nonce: &[u8]) -> Result<Vec<u8>, JsError> {
        let id = self.device.device_id().ok_or_else(|| err("not registered"))?;
        Ok(frame(0, C::Proof(gw::Proof { signature: self.device.sign_gateway_challenge(nonce, id).to_vec() })))
    }

    pub fn register(&self, nonce: &[u8], name: &str) -> Vec<u8> {
        let k = self.device.keys();
        frame(
            0,
            C::RegisterDevice(gw::RegisterDevice {
                kind: 2,
                name: name.chars().take(48).collect(),
                ed25519: k.ed25519.to_vec(),
                curve25519: k.curve25519.to_vec(),
                seal_key: k.seal_key.to_vec(),
                signature: self.device.sign_gateway_challenge(nonce, 0).to_vec(),
            }),
        )
    }

    #[wasm_bindgen(js_name = setDeviceId)]
    pub fn set_device_id(&mut self, id: &str) -> Result<(), JsError> {
        self.device.set_device_id(id.parse().map_err(|_| err("bad device id"))?).map_err(err)
    }

    /// A server frame as JSON (`type`, `requestId`, and its fields).
    pub fn decode(bytes: &[u8]) -> Result<String, JsError> {
        let f = ServerFrame::decode(bytes).map_err(|_| err("unreadable frame"))?;
        Ok(server_to_json(&f).to_string())
    }

    /// A client request. `kind` names it; `args` (JSON) carries its fields.
    /// Requests that need keys (publishing the master key, certifying this
    /// device, uploading prekeys) are filled in here.
    pub fn request(&mut self, request_id: u32, kind: &str, args: &str) -> Result<Vec<u8>, JsError> {
        let a: Value = if args.is_empty() { json!({}) } else { serde_json::from_str(args).map_err(err)? };
        let k = match kind {
            "publishMasterKey" => C::PublishMasterKey(gw::PublishMasterKey { public_key: self.master.public_key().to_vec() }),
            "certify" => {
                let device_id = self.device.device_id().ok_or_else(|| err("not registered"))?;
                C::CertifyDevice(gw::CertifyDevice { device_id, signature: self.master.certify(&self.device.keys()).msk_signature.to_vec() })
            }
            "keysUpload" => {
                let n = a["count"].as_u64().unwrap_or(0) as usize;
                let keys = self.device.publish_prekeys(n.min(100), a["fallback"].as_bool().unwrap_or(false)).map_err(err)?;
                C::KeysUpload(gw::KeysUpload {
                    prekeys: keys
                        .into_iter()
                        .map(|p| gw::Prekey { key_id: p.key_id, key: p.key.to_vec(), fallback: p.fallback, signature: p.signature.to_vec() })
                        .collect(),
                })
            }
            "devicesQuery" => C::DevicesQuery(gw::DevicesQuery { user_ids: ids(&a["userIds"])? }),
            "keysClaim" => C::KeysClaim(gw::KeysClaim { user_id: num(&a["userId"])? }),
            "ack" => C::Ack(gw::Ack { up_to_seq: num(&a["upToSeq"])? }),
            "revokeDevice" => C::RevokeDevice(gw::RevokeDevice { device_id: num(&a["deviceId"])? }),
            "backupPut" => C::BackupPut(gw::BackupPut { blob: unb64(&a["blob"])? }),
            "backupGet" => C::BackupGet(gw::Empty {}),
            "backupDelete" => C::BackupDelete(gw::Empty {}),
            "listMyDevices" => C::ListMyDevices(gw::Empty {}),
            "groupCreate" => C::GroupCreate(gw::GroupCreate { member_ids: ids(&a["memberIds"])? }),
            "groupGet" => C::GroupGet(gw::GroupRef { group_id: num(&a["groupId"])? }),
            "groupList" => C::GroupList(gw::Empty {}),
            "groupAdd" => C::GroupAdd(gw::GroupAdd { group_id: num(&a["groupId"])?, user_ids: ids(&a["userIds"])? }),
            "groupRemove" => C::GroupRemove(gw::GroupRemove { group_id: num(&a["groupId"])?, user_id: num(&a["userId"])? }),
            "attachmentTicket" => C::AttachmentTicket(gw::AttachmentTicket { size: num(&a["size"])? }),
            "pushSubscribe" => C::PushSubscribe(gw::PushSubscribe { endpoint: a["endpoint"].as_str().unwrap_or_default().to_string() }),
            "pushUnsubscribe" => C::PushUnsubscribe(gw::Empty {}),
            other => return Err(err(format!("unknown request {other}"))),
        };
        Ok(frame(request_id, k))
    }

    // ---- who is who ----

    /// Check a user's devices from a `devices` frame (JSON from `decode`).
    /// Returns `{"status": "ok"|"identityChanged"|"absent", "count": n}`.
    #[wasm_bindgen(js_name = checkDevices)]
    pub fn check_devices(&mut self, devices_frame: &str, user_id: &str) -> Result<String, JsError> {
        let v: Value = serde_json::from_str(devices_frame).map_err(err)?;
        let uid: u64 = user_id.parse().map_err(|_| err("bad user id"))?;
        let own = self.device.device_id().unwrap_or(0);
        let Some(u) = v["users"].as_array().into_iter().flatten().find(|u| num(&u["userId"]).ok() == Some(uid)) else {
            self.devices.insert(uid, Vec::new());
            return Ok(json!({ "status": "absent", "count": 0 }).to_string());
        };
        match self.trust.check(&user_devices_from_json(u)?) {
            Ok(checked) => {
                let list: Vec<TrustedDevice> = checked.devices.into_iter().filter(|d| d.keys().device_id != own).collect();
                let n = list.len();
                self.devices.insert(uid, list);
                Ok(json!({ "status": "ok", "count": n }).to_string())
            }
            Err(CoreError::IdentityChanged { .. }) => Ok(json!({ "status": "identityChanged", "count": 0 }).to_string()),
            Err(e) => Err(err(e)),
        }
    }

    #[wasm_bindgen(js_name = knownDevices)]
    pub fn known_devices(&self, user_id: &str) -> i32 {
        user_id.parse::<u64>().ok().and_then(|u| self.devices.get(&u)).map(|d| d.len() as i32).unwrap_or(-1)
    }

    #[wasm_bindgen(js_name = forgetDevices)]
    pub fn forget_devices(&mut self, user_id: &str) {
        if let Ok(u) = user_id.parse::<u64>() {
            self.devices.remove(&u);
        }
    }

    /// Does any device of this user still need a session (a prekey claim)?
    #[wasm_bindgen(js_name = needsClaim)]
    pub fn needs_claim(&self, user_id: &str) -> bool {
        let Ok(u) = user_id.parse::<u64>() else { return false };
        self.devices.get(&u).is_some_and(|l| l.iter().any(|d| !self.device.has_session(d) && !self.claims.contains_key(&d.keys().device_id)))
    }

    /// Keep the prekeys from a `keysBundle` frame for the next encryption.
    #[wasm_bindgen(js_name = addClaims)]
    pub fn add_claims(&mut self, bundle_frame: &str) -> Result<(), JsError> {
        let v: Value = serde_json::from_str(bundle_frame).map_err(err)?;
        for k in v["keys"].as_array().into_iter().flatten() {
            let p = &k["prekey"];
            if p.is_null() {
                continue;
            }
            let pk = SignedPrekey {
                key_id: p["keyId"].as_str().unwrap_or_default().to_string(),
                key: arr32(&unb64(&p["key"])?)?,
                fallback: p["fallback"].as_bool().unwrap_or(false),
                signature: unb64(&p["signature"])?.as_slice().try_into().map_err(|_| err("bad signature"))?,
            };
            self.claims.insert(num(&k["deviceId"])?, pk);
        }
        Ok(())
    }

    /// Encrypt `content` (JSON) for every known device of `users` (JSON array
    /// of ids) and return the Send frame. Throws "nothing to send" if no
    /// device could be reached.
    #[wasm_bindgen(js_name = sendFrame)]
    pub fn send_frame(&mut self, request_id: u32, content: &str, users: &str, ephemeral: bool, group_id: &str) -> Result<Vec<u8>, JsError> {
        let c = content_from_json(&serde_json::from_str(content).map_err(err)?)?;
        let users = ids(&serde_json::from_str(users).map_err(err)?)?;
        let mut items = Vec::new();
        for u in users {
            for d in self.devices.get(&u).cloned().unwrap_or_default() {
                let pk = self.claims.get(&d.keys().device_id).cloned();
                if let Ok(envelope) = self.device.encrypt(&d, pk.as_ref(), &c) {
                    self.claims.remove(&d.keys().device_id);
                    items.push(gw::SendItem { recipient_device_id: d.keys().device_id, envelope });
                }
            }
        }
        if items.is_empty() {
            return Err(err("nothing to send"));
        }
        let group_id = group_id.parse().unwrap_or(0);
        Ok(frame(request_id, C::Send(gw::Send { client_msg_id: c.msg_id.clone(), items, ephemeral, group_id })))
    }

    /// Decrypt a delivered envelope. Returns `{"ok": {sender, content}}` or
    /// `{"error": "unknownSender", "userId"}` (look their devices up, try
    /// again) / `"duplicate"` / `"undecryptable"`.
    pub fn decrypt(&mut self, envelope: &[u8]) -> String {
        let cache = &self.devices;
        let r = self.device.decrypt(envelope, |u, dev| cache.get(&u).and_then(|l| l.iter().find(|t| t.keys().device_id == dev).cloned()));
        match r {
            Ok(i) => json!({ "ok": { "sender": { "userId": i.sender.user_id.to_string(), "deviceId": i.sender.device_id.to_string() }, "content": content_to_json(&i.content) } }),
            Err(CoreError::UnknownSender { user_id, .. }) => json!({ "error": "unknownSender", "userId": user_id.to_string() }),
            Err(CoreError::Duplicate) => json!({ "error": "duplicate" }),
            Err(_) => json!({ "error": "undecryptable" }),
        }
        .to_string()
    }

    // ---- verification ----

    #[wasm_bindgen(js_name = verifyInfo)]
    pub fn verify_info(&self, peer: &str) -> Result<String, JsError> {
        let p: u64 = peer.parse().map_err(|_| err("bad user id"))?;
        let pending = self.trust.has_pending_change(p);
        Ok(match self.trust.pinned(p) {
            None => json!({ "safetyNumber": [], "verified": false, "pendingChange": pending }),
            Some((theirs, level)) => {
                let n = safety_number(self.device.user_id(), &self.master.public_key(), p, &theirs);
                json!({ "safetyNumber": display_groups(&n), "verified": level == TrustLevel::Verified, "pendingChange": pending })
            }
        }
        .to_string())
    }

    #[wasm_bindgen(js_name = markVerified)]
    pub fn mark_verified(&mut self, peer: &str, verified: bool) -> Result<(), JsError> {
        let p: u64 = peer.parse().map_err(|_| err("bad user id"))?;
        if verified {
            let (key, _) = self.trust.pinned(p).ok_or_else(|| err("their key is not known yet"))?;
            self.trust.mark_verified(p, &key).map_err(err)
        } else {
            self.trust.mark_unverified(p).map_err(err)
        }
    }

    #[wasm_bindgen(js_name = acknowledgeChange)]
    pub fn acknowledge_change(&mut self, peer: &str) -> Result<(), JsError> {
        let p: u64 = peer.parse().map_err(|_| err("bad user id"))?;
        self.trust.acknowledge_change(p).map_err(err)?;
        self.devices.remove(&p);
        Ok(())
    }

    // ---- backup and identity ----

    /// A new recovery code and the backup sealed with it: `{"code","blob"}`.
    #[wasm_bindgen(js_name = backupCreate)]
    pub fn backup_create(&self) -> Result<String, JsError> {
        let key = RecoveryKey::generate();
        let blob = seal_backup(&key, self.device.user_id(), &self.master, &self.trust).map_err(err)?;
        Ok(json!({ "code": key.to_code(), "blob": b64(&blob) }).to_string())
    }

    /// Re-seal the backup with a kept code (trust pins changed).
    #[wasm_bindgen(js_name = backupReseal)]
    pub fn backup_reseal(&self, code: &str) -> Result<String, JsError> {
        let key = RecoveryKey::from_code(code).map_err(err)?;
        Ok(b64(&seal_backup(&key, self.device.user_id(), &self.master, &self.trust).map_err(err)?))
    }

    /// Take over the identity in a backup (base64 blob) with its code.
    #[wasm_bindgen(js_name = restoreBackup)]
    pub fn restore_backup(&mut self, code: &str, blob: &str) -> Result<(), JsError> {
        let key = RecoveryKey::from_code(code).map_err(err)?;
        let blob = B64.decode(blob).map_err(|_| err("bad backup"))?;
        let (master, trust) = open_backup(&key, self.device.user_id(), &blob).map_err(|e| match e {
            CoreError::Undecryptable => err("That recovery code does not open your backup."),
            other => err(other),
        })?;
        self.trust = trust;
        self.trust.pin_own(self.device.user_id(), master.public_key());
        self.master = master;
        self.devices.clear();
        Ok(())
    }

    /// A new identity for the whole account (contacts are warned).
    #[wasm_bindgen(js_name = resetIdentity)]
    pub fn reset_identity(&mut self) {
        self.master = MasterKey::generate();
        self.trust.pin_own(self.device.user_id(), self.master.public_key());
        self.devices.clear();
    }

    // ---- rules, files, ids ----

    /// Throws when the content may not be sent (length, supporter perks...).
    pub fn validate(content: &str, supporter: bool) -> Result<(), JsError> {
        let c = content_from_json(&serde_json::from_str(content).map_err(err)?)?;
        validate_outgoing(&c, supporter).map_err(err)
    }

    /// What a receiver shows: `{"shown": "ok"}`, `{"shown":"truncated","text"}`
    /// or `{"shown":"gifAsText","text"}`.
    #[wasm_bindgen(js_name = receiveRules)]
    pub fn receive_rules_js(content: &str, sender_supporter: bool) -> Result<String, JsError> {
        let c = content_from_json(&serde_json::from_str(content).map_err(err)?)?;
        Ok(match receive_rules(&c, sender_supporter) {
            Shown::Ok => json!({ "shown": "ok" }),
            Shown::Truncated(t) => json!({ "shown": "truncated", "text": t }),
            Shown::GifAsText(t) => json!({ "shown": "gifAsText", "text": t }),
        }
        .to_string())
    }

    /// Seal a file: returns key (32) ‖ sha256 (32) ‖ ciphertext.
    #[wasm_bindgen(js_name = sealFile)]
    pub fn seal_file(bytes: &[u8]) -> Result<Vec<u8>, JsError> {
        let s = seal_attachment(bytes).map_err(err)?;
        let mut out = Vec::with_capacity(64 + s.ciphertext.len());
        out.extend_from_slice(s.key.as_slice());
        out.extend_from_slice(&s.sha256);
        out.extend_from_slice(&s.ciphertext);
        Ok(out)
    }

    #[wasm_bindgen(js_name = openFile)]
    pub fn open_file(key_hex: &str, sha256_hex: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
        let key = hex::decode(key_hex).map_err(|_| err("bad key"))?;
        let sha = hex::decode(sha256_hex).map_err(|_| err("bad hash"))?;
        Ok(open_attachment(&key, &sha, ciphertext).map_err(err)?.to_vec())
    }

    #[wasm_bindgen(js_name = newMessageId)]
    pub fn new_message_id_js() -> String {
        hex::encode(new_message_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_json_round_trips_every_body() {
        let bodies = [
            json!({ "type": "text", "text": "hi", "replyTo": "" }),
            json!({ "type": "receipt", "receiptKind": "read", "msgIds": ["00112233445566778899aabbccddeeff"] }),
            json!({ "type": "typing", "active": true }),
            json!({ "type": "edit", "target": "00112233445566778899aabbccddeeff", "text": "x" }),
            json!({ "type": "delete", "target": "00112233445566778899aabbccddeeff" }),
            json!({ "type": "reaction", "target": "00112233445566778899aabbccddeeff", "emoji": "🔥", "remove": false }),
            json!({ "type": "gif", "provider": "giphy", "id": "a", "url": "https://media.giphy.com/a.gif", "width": 1, "height": 2, "title": "t" }),
            json!({ "type": "invite", "slug": "g", "title": "G", "steamLobby": "1", "hostSteamId": "2", "expiresAt": 3 }),
            json!({ "type": "groupMeta", "name": "crew" }),
            json!({ "type": "file", "id": "5", "token": "ab", "key": "00", "sha256": "11", "name": "f", "mime": "m", "size": 9, "width": 0, "height": 0 }),
            json!({ "type": "call", "callId": "00112233445566778899aabbccddeeff", "callKind": "offer", "payload": "sdp" }),
        ];
        for b in bodies {
            let v = json!({ "msgId": "00112233445566778899aabbccddeeff", "conversationId": "646d3a", "sentAt": 7, "body": b });
            let c = content_from_json(&v).unwrap_or_else(|_| panic!("{v}"));
            assert_eq!(content_to_json(&c), v);
        }
    }

    #[test]
    fn two_web_devices_talk_through_the_frames() {
        // Alice and Bob as the page would drive them, minus the network.
        let mut alice = Kryo::create("1").unwrap();
        let mut bob = Kryo::create("2").unwrap();
        alice.set_device_id("11").unwrap();
        bob.set_device_id("22").unwrap();
        // Bob publishes prekeys; Alice gets his device list and a claim.
        let upload = gw::ClientFrame::decode(bob.request(1, "keysUpload", r#"{"count":2,"fallback":true}"#).unwrap().as_slice()).unwrap();
        let Some(C::KeysUpload(u)) = upload.kind else { panic!() };
        let cert = bob.master.certify(&bob.device.keys());
        let devices = gw::Devices {
            users: vec![gw::UserDevicesInfo {
                user_id: 2,
                master_key: bob.master.public_key().to_vec(),
                devices: vec![gw::DeviceInfo {
                    device_id: 22,
                    kind: 2,
                    ed25519: cert.keys.ed25519.to_vec(),
                    curve25519: cert.keys.curve25519.to_vec(),
                    seal_key: cert.keys.seal_key.to_vec(),
                    msk_signature: cert.msk_signature.to_vec(),
                }],
            }],
        };
        let dj = server_to_json(&ServerFrame { request_id: 3, kind: Some(S::Devices(devices)) }).to_string();
        assert!(alice.check_devices(&dj, "2").unwrap().contains("\"ok\""));
        assert!(alice.needs_claim("2"));
        let bundle = gw::KeysBundle { user_id: 2, keys: vec![gw::ClaimedKey { device_id: 22, prekey: Some(u.prekeys[0].clone()) }] };
        alice.add_claims(&server_to_json(&ServerFrame { request_id: 4, kind: Some(S::KeysBundle(bundle)) }).to_string()).unwrap();
        let content = json!({ "msgId": Kryo::new_message_id_js(), "conversationId": "646d3a", "sentAt": 1, "body": { "type": "text", "text": "hello bob", "replyTo": "" } });
        let send = alice.send_frame(5, &content.to_string(), "[\"2\"]", false, "").unwrap();
        let Some(C::Send(s)) = gw::ClientFrame::decode(send.as_slice()).unwrap().kind else { panic!() };
        // Bob decrypts once he knows Alice's device.
        let r: Value = serde_json::from_str(&bob.decrypt(&s.items[0].envelope)).unwrap();
        assert_eq!(r["error"], "unknownSender");
        let acert = alice.master.certify(&alice.device.keys());
        let adevices = gw::Devices {
            users: vec![gw::UserDevicesInfo {
                user_id: 1,
                master_key: alice.master.public_key().to_vec(),
                devices: vec![gw::DeviceInfo {
                    device_id: 11,
                    kind: 2,
                    ed25519: acert.keys.ed25519.to_vec(),
                    curve25519: acert.keys.curve25519.to_vec(),
                    seal_key: acert.keys.seal_key.to_vec(),
                    msk_signature: acert.msk_signature.to_vec(),
                }],
            }],
        };
        bob.check_devices(&server_to_json(&ServerFrame { request_id: 6, kind: Some(S::Devices(adevices)) }).to_string(), "1").unwrap();
        let r: Value = serde_json::from_str(&bob.decrypt(&s.items[0].envelope)).unwrap();
        assert_eq!(r["ok"]["content"]["body"]["text"], "hello bob");
        assert_eq!(r["ok"]["sender"]["userId"], "1");
        // State survives a restore, sessions included.
        let restored = Kryo::restore(&bob.state().unwrap()).unwrap();
        assert_eq!(restored.device_id().as_deref(), Some("22"));
        assert_eq!(restored.master_public(), bob.master_public());
        // Safety numbers match on both sides.
        let a: Value = serde_json::from_str(&alice.verify_info("2").unwrap()).unwrap();
        let b: Value = serde_json::from_str(&bob.verify_info("1").unwrap()).unwrap();
        assert_eq!(a["safetyNumber"], b["safetyNumber"]);
    }

    #[test]
    fn files_and_backups_round_trip() {
        let sealed = Kryo::seal_file(b"a file").unwrap();
        let (key, rest) = sealed.split_at(32);
        let (sha, ct) = rest.split_at(32);
        assert_eq!(Kryo::open_file(&hex::encode(key), &hex::encode(sha), ct).unwrap(), b"a file");
        let alice = Kryo::create("1").unwrap();
        let b: Value = serde_json::from_str(&alice.backup_create().unwrap()).unwrap();
        let mut other = Kryo::create("1").unwrap();
        assert_ne!(other.master_public(), alice.master_public());
        other.restore_backup(b["code"].as_str().unwrap(), b["blob"].as_str().unwrap()).unwrap();
        assert_eq!(other.master_public(), alice.master_public());
    }
}
