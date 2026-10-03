//! Focused session checks: one refresh per invalid session, one retry,
//! single-flight rotation, and expected-credential clearing.

#[path = "../src/client.rs"]
mod client;

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use client::{Client, ClientError, SessionCredentials, SessionStore};
use common::{response, serve};
use serde_json::json;

fn token(seed: &str) -> String {
    format!("{seed}{}", "A".repeat(43 - seed.len()))
}

fn credentials(access_seed: &str, refresh_seed: &str) -> SessionCredentials {
    SessionCredentials {
        access_token: token(access_seed),
        refresh_token: token(refresh_seed),
        expires_at: "2026-01-01T00:00:00Z".into(),
        refresh_expires_at: "2026-01-02T00:00:00Z".into(),
        user_id: "user-1".into(),
        session_id: "session-1".into(),
    }
}

fn refresh_body(access_seed: &str, refresh_seed: &str) -> String {
    let value = json!({
        "access_token": token(access_seed),
        "refresh_token": token(refresh_seed),
        "expires_at": "2026-01-01T00:00:00Z",
        "refresh_expires_at": "2026-01-02T00:00:00Z",
        "user_id": "user-1",
        "session_id": "session-1",
    });
    value.to_string()
}

#[derive(Default)]
struct MemoryStore {
    origin: String,
    state: Mutex<Option<SessionCredentials>>,
    refresh_calls: AtomicUsize,
    cleared: Mutex<Vec<SessionCredentials>>,
}

impl MemoryStore {
    fn new(origin: &str, credentials: SessionCredentials) -> Arc<Self> {
        Arc::new(Self {
            origin: origin.to_owned(),
            state: Mutex::new(Some(credentials)),
            ..Self::default()
        })
    }

    fn current(&self) -> SessionCredentials {
        self.state
            .lock()
            .expect("store state")
            .clone()
            .unwrap_or_else(empty_credentials)
    }
}

fn empty_credentials() -> SessionCredentials {
    SessionCredentials {
        access_token: String::new(),
        refresh_token: String::new(),
        expires_at: String::new(),
        refresh_expires_at: String::new(),
        user_id: String::new(),
        session_id: String::new(),
    }
}

impl SessionStore for MemoryStore {
    fn bound_origin(&self) -> String {
        self.origin.clone()
    }

    fn credentials(&self) -> SessionCredentials {
        self.current()
    }

    fn refresh(
        &self,
        operation: &mut dyn FnMut(SessionCredentials) -> Result<SessionCredentials, ClientError>,
    ) -> Result<SessionCredentials, ClientError> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        let latest = operation(self.current())?;
        *self.state.lock().expect("store state") = Some(latest.clone());
        Ok(latest)
    }

    fn clear(&self, expected: &SessionCredentials) {
        let mut state = self.state.lock().expect("store state");
        if state.as_ref() == Some(expected) {
            *state = None;
        }
        self.cleared.lock().expect("cleared log").push(expected.clone());
    }
}

fn operation_status_and_code(error: ClientError) -> (u16, String) {
    match error {
        ClientError::Operation(error) => (error.status, error.code),
        other => panic!("expected operation error, got {other}"),
    }
}

fn unwrap_credentials(store: &MemoryStore) -> SessionCredentials {
    store.state.lock().expect("store state").clone().expect("credentials present")
}

#[test]
fn refreshes_once_and_retries_original() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 200 OK", &refresh_body("new_access", "new_refresh")),
        response("HTTP/1.1 200 OK", "{\"ok\":true}"),
    ]);
    let store = MemoryStore::new(&origin, credentials("old_access", "old_refresh"));
    let client = Client::with_timeout(&origin, std::time::Duration::from_secs(10))
        .expect("valid origin")
        .with_session(store.clone())
        .expect("valid session");

    let value = client.invoke("catalog.find", &json!({ "id": "one" })).expect("retried call");
    assert_eq!(value, json!({ "ok": true }));

    let first = receiver.recv().expect("original request");
    assert_eq!(first.path, "/catalog.find");
    assert_eq!(first.authorization.as_deref(), Some(format!("Bearer {}", token("old_access"))).as_deref());
    let second = receiver.recv().expect("refresh request");
    assert_eq!(second.path, "/auth.refresh");
    assert_eq!(second.authorization, None);
    assert!(second.body.contains(&token("old_refresh")));
    let third = receiver.recv().expect("retried request");
    assert_eq!(third.path, "/catalog.find");
    assert_eq!(third.authorization.as_deref(), Some(format!("Bearer {}", token("new_access"))).as_deref());

    let current = unwrap_credentials(&store);
    assert_eq!(current.access_token, token("new_access"));
    assert_eq!(current.refresh_token, token("new_refresh"));
    assert_eq!(store.refresh_calls.load(Ordering::SeqCst), 1);
    assert!(store.cleared.lock().expect("cleared log").is_empty());
}

#[test]
fn keeps_business_failures_and_never_refreshes_refresh_calls() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 409 Conflict", "{\"error\":\"out_of_stock\"}"),
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"forbidden\"}"),
    ]);
    let store = MemoryStore::new(&origin, credentials("access", "refresh"));
    let client = Client::with_timeout(&origin, std::time::Duration::from_secs(10))
        .expect("valid origin")
        .with_session(store.clone())
        .expect("valid session");

    let (status, code) = operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!((status, code.as_str()), (409, "out_of_stock"));

    let (status, code) = operation_status_and_code(client.invoke("auth.refresh", &json!({})).unwrap_err());
    assert_eq!((status, code.as_str()), (401, "invalid_token"));

    let (status, code) = operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!((status, code.as_str()), (401, "forbidden"));

    assert_eq!(receiver.recv().expect("recorded").path, "/catalog.find");
    assert_eq!(receiver.recv().expect("recorded").path, "/auth.refresh");
    assert_eq!(receiver.recv().expect("recorded").path, "/catalog.find");
    assert_eq!(store.refresh_calls.load(Ordering::SeqCst), 0);
    assert!(store.cleared.lock().expect("cleared log").is_empty());
}

#[test]
fn clears_only_expected_credential_when_refresh_rejected() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
    ]);
    let store = MemoryStore::new(&origin, credentials("access", "refresh"));
    let client = Client::with_timeout(&origin, std::time::Duration::from_secs(10))
        .expect("valid origin")
        .with_session(store.clone())
        .expect("valid session");

    let (status, code) = operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!((status, code.as_str()), (401, "invalid_token"));

    let cleared = store.cleared.lock().expect("cleared log");
    assert_eq!(cleared.len(), 1);
    assert_eq!(cleared[0].access_token, token("access"));
    assert!(store.state.lock().expect("store state").is_none());
    drop(cleared);
    assert_eq!(receiver.recv().expect("recorded").path, "/catalog.find");
    assert_eq!(receiver.recv().expect("recorded").path, "/auth.refresh");
}

#[test]
fn keeps_rotated_credentials_without_second_refresh() {
    struct OnceRotated {
        origin: String,
        state: Mutex<Option<SessionCredentials>>,
        reads: AtomicUsize,
    }
    impl SessionStore for OnceRotated {
        fn bound_origin(&self) -> String {
            self.origin.clone()
        }

        fn credentials(&self) -> SessionCredentials {
            let read = self.reads.fetch_add(1, Ordering::SeqCst);
            if read < 2 {
                return self
                    .state
                    .lock()
                    .expect("store state")
                    .clone()
                    .expect("initial credentials");
            }
            let rotated = credentials("new_access", "new_refresh");
            *self.state.lock().expect("store state") = Some(rotated.clone());
            rotated
        }

        fn refresh(
            &self,
            _operation: &mut dyn FnMut(SessionCredentials) -> Result<SessionCredentials, ClientError>,
        ) -> Result<SessionCredentials, ClientError> {
            panic!("rotation must not call the refresh operation");
        }

        fn clear(&self, _expected: &SessionCredentials) {
            panic!("rotation must not clear credentials");
        }
    }

    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 200 OK", "{\"ok\":true}"),
    ]);
    let store = Arc::new(OnceRotated {
        origin: origin.clone(),
        state: Mutex::new(Some(credentials("old_access", "old_refresh"))),
        reads: AtomicUsize::new(0),
    });
    let client = Client::with_timeout(&origin, std::time::Duration::from_secs(10))
        .expect("valid origin")
        .with_session(store.clone())
        .expect("valid session");

    let value = client.invoke("catalog.find", &json!({})).expect("call succeeds");
    assert_eq!(value, json!({ "ok": true }));
    assert_eq!(receiver.recv().expect("recorded").path, "/catalog.find");
    assert_eq!(receiver.recv().expect("recorded").path, "/catalog.find");
}

#[test]
fn single_flight_rotates_once_for_concurrent_callers() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 200 OK", &refresh_body("new_access", "new_refresh")),
        response("HTTP/1.1 200 OK", "{\"which\":1}"),
        response("HTTP/1.1 200 OK", "{\"which\":2}"),
    ]);
    let store = MemoryStore::new(&origin, credentials("old_access", "old_refresh"));
    let client = Arc::new(
        Client::with_timeout(&origin, std::time::Duration::from_secs(10))
            .expect("valid origin")
            .with_session(store.clone())
            .expect("valid session"),
    );
    let first = {
        let client = client.clone();
        std::thread::spawn(move || client.invoke("catalog.find", &json!({})))
    };
    let second = {
        let client = client.clone();
        std::thread::spawn(move || client.invoke("catalog.find", &json!({})))
    };
    let first_value = first.join().expect("first thread").expect("first result");
    let second_value = second.join().expect("second thread").expect("second result");
    let mut results = vec![
        first_value.get("which").and_then(serde_json::Value::as_i64).expect("which"),
        second_value.get("which").and_then(serde_json::Value::as_i64).expect("which"),
    ];
    results.sort_unstable();
    assert_eq!(results, vec![1, 2]);

    let mut refresh_requests = 0;
    for _ in 0..5 {
        if receiver.recv().expect("recorded").path == "/auth.refresh" {
            refresh_requests += 1;
        }
    }
    assert_eq!(refresh_requests, 1);
    assert_eq!(unwrap_credentials(&store).access_token, token("new_access"));
}

#[test]
fn separate_clients_on_one_store_share_single_flight() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response("HTTP/1.1 200 OK", &refresh_body("new_access", "new_refresh")),
        response("HTTP/1.1 200 OK", "{\"which\":1}"),
        response("HTTP/1.1 200 OK", "{\"which\":2}"),
    ]);
    let store = MemoryStore::new(&origin, credentials("old_access", "old_refresh"));
    let build = || {
        Client::with_timeout(&origin, std::time::Duration::from_secs(10))
            .expect("valid origin")
            .with_session(store.clone())
            .expect("valid session")
    };
    let first_client = Arc::new(build());
    let second_client = Arc::new(build());
    let first = {
        let client = first_client.clone();
        std::thread::spawn(move || client.invoke("catalog.find", &json!({})))
    };
    let second = {
        let client = second_client.clone();
        std::thread::spawn(move || client.invoke("catalog.find", &json!({})))
    };
    let results: Vec<i64> = [first, second]
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .expect("thread result")
                .expect("call result")
                .get("which")
                .and_then(serde_json::Value::as_i64)
                .expect("which")
        })
        .collect();
    let mut sorted = results;
    sorted.sort_unstable();
    assert_eq!(sorted, vec![1, 2]);

    let mut refresh_requests = 0;
    for _ in 0..5 {
        if receiver.recv().expect("recorded").path == "/auth.refresh" {
            refresh_requests += 1;
        }
    }
    assert_eq!(refresh_requests, 1);
    assert_eq!(store.refresh_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn rejects_wrong_origin_store_before_any_request() {
    let (origin, receiver) = serve(&[response("HTTP/1.1 200 OK", "{}")]);
    let store = MemoryStore::new("https://elsewhere.example.com", credentials("access", "refresh"));
    let client = Client::with_timeout(&origin, std::time::Duration::from_secs(10))
        .expect("valid origin");
    let error = match client.with_session(store) {
        Err(ClientError::Protocol(message)) => message,
        Err(other) => panic!("expected protocol error, got {other}"),
        Ok(_) => panic!("a wrong-origin store must not attach"),
    };
    assert_eq!(error, "session store is bound to a different origin");
    assert!(
        receiver.try_recv().is_err(),
        "no credential or request may reach another origin"
    );
}
