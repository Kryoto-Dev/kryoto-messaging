use km_core::proto::{content::Body, Content, Text};
use km_core::{new_message_id, DeviceKind, LocalDevice, MasterKey, TrustStore, UserDevices};
use km_store_sqlcipher::Store;
#[cfg(feature = "sqlcipher")]
use km_store_sqlcipher::StoreError;

const KEY: [u8; 32] = [7; 32];

fn temp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("km-store-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("chat.db")
}

fn msg(text: &str) -> Content {
    Content {
        msg_id: new_message_id().to_vec(),
        conversation_id: vec![1],
        sent_at_ms: 1,
        body: Some(Body::Text(Text { text: text.into(), reply_to: vec![] })),
    }
}

#[test]
fn state_round_trips_and_keeps_working() {
    let path = temp_path("roundtrip");
    let alice_master = MasterKey::generate();
    let mut alice = LocalDevice::new(1, DeviceKind::Desktop);
    alice.set_device_id(11).unwrap();
    let mut bob = LocalDevice::new(2, DeviceKind::Desktop);
    bob.set_device_id(22).unwrap();
    let bob_master = MasterKey::generate();
    let bob_entry = UserDevices { user_id: 2, master_key: bob_master.public_key(), devices: vec![bob_master.certify(&bob.keys())] };
    let alice_entry = UserDevices { user_id: 1, master_key: alice_master.public_key(), devices: vec![alice_master.certify(&alice.keys())] };

    let mut trust = TrustStore::new();
    let bob_dev = trust.check(&bob_entry).unwrap().devices.remove(0);
    let pk = bob.publish_prekeys(1, true).unwrap().remove(0);
    let first = alice.encrypt(&bob_dev, Some(&pk), &msg("first")).unwrap();

    {
        let store = Store::open(&path, &KEY).unwrap();
        store.save_device(&alice).unwrap();
        store.save_trust(&trust).unwrap();
        store.save_master_key(&alice_master).unwrap();
    }

    // Reopen: everything is back and the session continues.
    let store = Store::open(&path, &KEY).unwrap();
    let mut alice2 = store.load_device().unwrap().unwrap();
    let mut trust2 = store.load_trust().unwrap();
    assert_eq!(store.load_master_key().unwrap().unwrap().public_key(), alice_master.public_key());
    assert_eq!(trust2.pinned(2).unwrap().0, bob_master.public_key());

    let mut bob_trust = TrustStore::new();
    let alice_dev = bob_trust.check(&alice_entry).unwrap().devices.remove(0);
    let lookup = |d: &km_core::TrustedDevice| { let d = d.clone(); move |_, _| Some(d) };
    bob.decrypt(&first, lookup(&alice_dev)).unwrap();
    let bob_dev = trust2.check(&bob_entry).unwrap().devices.remove(0);
    let second = alice2.encrypt(&bob_dev, None, &msg("second, after reopening")).unwrap();
    bob.decrypt(&second, lookup(&alice_dev)).unwrap();
}

#[test]
fn empty_store_has_nothing() {
    let store = Store::open_in_memory(&KEY).unwrap();
    assert!(store.load_device().unwrap().is_none());
    assert!(store.load_master_key().unwrap().is_none());
    assert!(store.load_trust().unwrap().pinned(1).is_none());
}

/// The point of SQLCipher: the file on disk is noise without the key.
#[cfg(feature = "sqlcipher")]
#[test]
fn the_file_is_encrypted_and_the_key_matters() {
    let path = temp_path("encrypted");
    {
        let store = Store::open(&path, &KEY).unwrap();
        // The saved state is JSON with recognisable field names; none of them
        // may be findable in the file.
        let mut trust = TrustStore::new();
        trust.pin_own(1, [9; 32]);
        store.save_trust(&trust).unwrap();
        let mut d = LocalDevice::new(1, DeviceKind::Desktop);
        d.set_device_id(1).unwrap();
        store.save_device(&d).unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    assert!(!bytes.starts_with(b"SQLite format 3"), "file has a plain SQLite header");
    let hay = String::from_utf8_lossy(&bytes);
    // Long enough not to turn up by chance in tens of kilobytes of
    // ciphertext: a two-letter table name like `kv` does, about every other run.
    for needle in ["seal_secret", "sessions", "master_key", "CREATE TABLE"] {
        assert!(!hay.contains(needle), "found {needle:?} in the database file");
    }

    assert!(matches!(Store::open(&path, &[8; 32]), Err(StoreError::WrongKey)));

    let store = Store::open(&path, &KEY).unwrap();
    store.rekey(&[5; 32]).unwrap();
    drop(store);
    assert!(matches!(Store::open(&path, &KEY), Err(StoreError::WrongKey)));
    assert!(Store::open(&path, &[5; 32]).unwrap().load_device().unwrap().is_some());
}

mod messages {
    use km_store_sqlcipher::{NewMessage, Status, Store};

    const KEY: [u8; 32] = [3; 32];

    fn msg<'a>(id: &'a [u8], conv: &'a [u8], sender: u64, outgoing: bool, at: u64, body: &'a str) -> NewMessage<'a> {
        NewMessage {
            msg_id: id,
            conversation_id: conv,
            peer_user_id: Some(2),
            sender_user: sender,
            sender_device: 9,
            outgoing,
            sent_at: at,
            received_at: at,
            kind: "text",
            body,
            reply_to: None,
            status: if outgoing { Status::Sending } else { Status::Received },
        }
    }

    #[test]
    fn store_list_and_page_messages() {
        let s = Store::open_in_memory(&KEY).unwrap();
        let conv = b"dm:conversation".to_vec();
        assert!(s.insert_message(&msg(&[1; 16], &conv, 1, true, 100, "hi")).unwrap());
        assert!(s.insert_message(&msg(&[2; 16], &conv, 2, false, 200, "hello back")).unwrap());
        assert!(!s.insert_message(&msg(&[2; 16], &conv, 2, false, 200, "dup")).unwrap(), "duplicates are ignored");
        let all = s.messages(&conv, None, 50).unwrap();
        assert_eq!(all.iter().map(|m| m.body.as_str()).collect::<Vec<_>>(), ["hi", "hello back"]);
        assert_eq!(s.messages(&conv, Some(200), 50).unwrap().len(), 1, "paging by time");
        let convs = s.conversations().unwrap();
        assert_eq!(convs.len(), 1);
        assert_eq!(convs[0].unread, 1);
        assert_eq!(convs[0].last.as_ref().unwrap().body, "hello back");
    }

    #[test]
    fn status_only_moves_forward() {
        let s = Store::open_in_memory(&KEY).unwrap();
        let conv = b"c".to_vec();
        s.insert_message(&msg(&[1; 16], &conv, 1, true, 1, "x")).unwrap();
        assert!(s.advance_status(&[1; 16], Status::Sent).unwrap());
        assert!(s.advance_status(&[1; 16], Status::Read).unwrap());
        assert!(!s.advance_status(&[1; 16], Status::Delivered).unwrap(), "a late delivery receipt does not undo read");
        assert_eq!(s.message(&[1; 16]).unwrap().unwrap().status, Status::Read);
    }

    #[test]
    fn only_the_author_edits_or_deletes() {
        let s = Store::open_in_memory(&KEY).unwrap();
        let conv = b"c".to_vec();
        s.insert_message(&msg(&[1; 16], &conv, 7, false, 1, "original")).unwrap();
        assert!(!s.apply_edit(&[1; 16], 8, "forged", 2).unwrap(), "someone else cannot edit it");
        assert!(s.apply_edit(&[1; 16], 7, "fixed", 2).unwrap());
        let m = s.message(&[1; 16]).unwrap().unwrap();
        assert_eq!((m.body.as_str(), m.edited_at), ("fixed", Some(2)));
        assert!(!s.apply_delete(&[1; 16], 8).unwrap());
        s.apply_reaction(&[1; 16], 8, "🔥", false).unwrap();
        assert!(s.apply_delete(&[1; 16], 7).unwrap());
        let m = s.message(&[1; 16]).unwrap().unwrap();
        assert!(m.deleted && m.body.is_empty() && m.reactions.is_empty(), "the text and reactions are gone");
        assert!(!s.apply_edit(&[1; 16], 7, "too late", 3).unwrap());
    }

    #[test]
    fn reactions_group_by_emoji() {
        let s = Store::open_in_memory(&KEY).unwrap();
        let conv = b"c".to_vec();
        s.insert_message(&msg(&[1; 16], &conv, 7, false, 1, "x")).unwrap();
        s.apply_reaction(&[1; 16], 1, "🔥", false).unwrap();
        s.apply_reaction(&[1; 16], 2, "🔥", false).unwrap();
        s.apply_reaction(&[1; 16], 2, "😂", false).unwrap();
        s.apply_reaction(&[1; 16], 2, "😂", true).unwrap();
        let r = s.message(&[1; 16]).unwrap().unwrap().reactions;
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].emoji, "🔥");
        assert_eq!(r[0].user_ids, ["1", "2"]);
        assert!(!s.apply_reaction(&[9; 16], 1, "🔥", false).unwrap(), "no message, no reaction");
    }

    #[test]
    fn reading_clears_unread_and_reports_what_to_receipt() {
        let s = Store::open_in_memory(&KEY).unwrap();
        let conv = b"c".to_vec();
        s.insert_message(&msg(&[1; 16], &conv, 2, false, 10, "a")).unwrap();
        s.insert_message(&msg(&[2; 16], &conv, 2, false, 20, "b")).unwrap();
        s.insert_message(&msg(&[3; 16], &conv, 1, true, 30, "mine")).unwrap();
        let read = s.mark_read(&conv, 25).unwrap();
        assert_eq!(read.len(), 2);
        assert!(s.mark_read(&conv, 25).unwrap().is_empty(), "receipts go out once");
        assert_eq!(s.conversations().unwrap()[0].unread, 0);
    }

    #[test]
    fn search_is_local_and_case_insensitive() {
        let s = Store::open_in_memory(&KEY).unwrap();
        let conv = b"c".to_vec();
        s.insert_message(&msg(&[1; 16], &conv, 2, false, 10, "Lethal Company tonight?")).unwrap();
        s.insert_message(&msg(&[2; 16], &conv, 2, false, 20, "sure")).unwrap();
        assert_eq!(s.search("lethal", 10).unwrap().len(), 1);
        assert_eq!(s.search("%", 10).unwrap().len(), 2, "wildcards are not special");
    }

    #[test]
    fn messages_survive_reopening() {
        let dir = std::env::temp_dir().join(format!("km-msg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("m.db");
        let _ = std::fs::remove_file(&path);
        {
            let s = Store::open(&path, &KEY).unwrap();
            s.insert_message(&msg(&[1; 16], b"c", 2, false, 10, "kept")).unwrap();
            s.set_setting("read_receipts", "off").unwrap();
        }
        let s = Store::open(&path, &KEY).unwrap();
        assert_eq!(s.messages(b"c", None, 10).unwrap()[0].body, "kept");
        assert_eq!(s.setting("read_receipts").unwrap().as_deref(), Some("off"));
    }
}
