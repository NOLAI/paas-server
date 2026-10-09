use libpep::contexts::EncryptionContext;
use paas_server::session_storage::{
    is_session_of, InMemorySessionStorage, SessionStorage, ToSessionKey,
};
use std::time::Duration;

fn storage() -> InMemorySessionStorage {
    InMemorySessionStorage::new(Duration::from_secs(3600), 10)
}

fn ids(sessions: Vec<EncryptionContext>) -> Vec<String> {
    sessions
        .iter()
        .map(|s| s.to_key_string().unwrap())
        .collect()
}

#[test]
fn is_session_of_requires_exact_username() {
    assert!(is_session_of("alice_ab12cd34ef", "alice"));
    assert!(is_session_of("al_x_ab12cd34ef", "al_x"));
    assert!(!is_session_of("alice_ab12cd34ef", "al"));
    assert!(!is_session_of("al_x_ab12cd34ef", "al"));
    assert!(!is_session_of("alice_", "alice"));
    assert!(!is_session_of("alice", "alice"));
}

#[test]
fn listing_does_not_leak_sessions_of_prefixed_usernames() {
    let storage = storage();
    let alice_id = storage.start_session("alice".to_string()).unwrap();
    let al_x_id = storage.start_session("al_x".to_string()).unwrap();
    let al_id = storage.start_session("al".to_string()).unwrap();

    assert_eq!(
        ids(storage.get_sessions_for_user("al".to_string()).unwrap()),
        vec![al_id]
    );
    assert_eq!(
        ids(storage.get_sessions_for_user("alice".to_string()).unwrap()),
        vec![alice_id]
    );
    assert_eq!(
        ids(storage.get_sessions_for_user("al_x".to_string()).unwrap()),
        vec![al_x_id]
    );
    assert!(storage
        .get_sessions_for_user("zoe".to_string())
        .unwrap()
        .is_empty());
}

#[test]
fn session_exists_is_scoped_to_owner() {
    let storage = storage();
    let al_x_id = storage.start_session("al_x".to_string()).unwrap();
    let ctx = EncryptionContext::from(&al_x_id);

    assert!(storage
        .session_exists("al_x".to_string(), ctx.clone())
        .unwrap());
    assert!(!storage.session_exists("al".to_string(), ctx).unwrap());
}

#[test]
fn end_session_removes_only_own_session() {
    let storage = storage();
    let alice_id = storage.start_session("alice".to_string()).unwrap();
    let ctx = EncryptionContext::from(&alice_id);

    storage.end_session("al".to_string(), ctx.clone()).unwrap();
    assert!(storage
        .session_exists("alice".to_string(), ctx.clone())
        .unwrap());

    storage
        .end_session("alice".to_string(), ctx.clone())
        .unwrap();
    assert!(!storage.session_exists("alice".to_string(), ctx).unwrap());
}

#[test]
fn is_healthy_succeeds() {
    assert!(storage().is_healthy().is_ok());
}
