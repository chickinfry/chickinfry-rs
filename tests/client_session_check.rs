//! Focused session checks: one refresh per invalid session, one retry,
//! single-flight rotation, and expected-credential clearing.

#[path = "../src/client.rs"]
mod client;

mod common;
#[path = "common/error.rs"]
mod error;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

use base64::Engine;
use client::{Client, ClientError, SessionCredentials, SessionStore};
use common::{response, serve, serve_with};
use error::assert_safe_protocol;
use serde_json::json;
use sha2::{Digest, Sha256};

fn token(seed: &str) -> String {
    let name = std::thread::current()
        .name()
        .unwrap_or("fixture")
        .to_owned();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(format!("{name}:{seed}").as_bytes()))
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
    save_failure: Option<ClientError>,
    save_barrier: Option<(std::sync::mpsc::Sender<()>, Arc<Barrier>)>,
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
        if let Some(error) = &self.save_failure {
            return Err(error.clone());
        }
        if let Some((arrived, release)) = &self.save_barrier {
            arrived.send(()).unwrap();
            release.wait();
        }
        *self.state.lock().expect("store state") = Some(latest.clone());
        Ok(latest)
    }

    fn clear(&self, expected: &SessionCredentials) {
        let mut state = self.state.lock().expect("store state");
        if state.as_ref() == Some(expected) {
            *state = None;
        }
        self.cleared
            .lock()
            .expect("cleared log")
            .push(expected.clone());
    }
}

fn operation_status_and_code(error: ClientError) -> (u16, String) {
    match error {
        ClientError::Operation(error) => (error.status, error.code),
        other => panic!("expected operation error, got {other}"),
    }
}

fn unwrap_credentials(store: &MemoryStore) -> SessionCredentials {
    store
        .state
        .lock()
        .expect("store state")
        .clone()
        .expect("credentials present")
}

#[test]
fn refreshes_once_and_retries_original() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
        response(
            "HTTP/1.1 200 OK",
            &refresh_body("new_access", "new_refresh"),
        ),
        response("HTTP/1.1 200 OK", "{\"ok\":true}"),
    ]);
    let store = MemoryStore::new(&origin, credentials("old_access", "old_refresh"));
    let client = Client::with_timeout(&origin, std::time::Duration::from_secs(10))
        .expect("valid origin")
        .with_session(store.clone())
        .expect("valid session");

    #[cfg(feature = "conformance")]
    let events = Arc::new(Mutex::new(Vec::new()));
    let invoke = || client.invoke("catalog.find", &json!({ "id": "one" }));
    #[cfg(feature = "conformance")]
    let result = client::conformance::observe(
        Arc::new({
            let events = events.clone();
            move |event| events.lock().unwrap().push(event)
        }),
        invoke,
    );
    #[cfg(not(feature = "conformance"))]
    let result = invoke();
    let value = result.expect("retried call");
    #[cfg(feature = "conformance")]
    {
        use client::conformance::Event;
        let events = events.lock().unwrap();
        assert!(matches!(events[0], Event::Entered));
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::OriginalRejected { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::RefreshParticipation { leader: true, .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, Event::Sending { .. }))
                .count(),
            3
        );
    }
    assert_eq!(value, json!({ "ok": true }));

    let first = receiver.recv().expect("original request");
    assert_eq!(first.path, "/catalog.find");
    assert_eq!(
        first.authorization.as_deref(),
        Some(format!("Bearer {}", token("old_access"))).as_deref()
    );
    let second = receiver.recv().expect("refresh request");
    assert_eq!(second.path, "/auth.refresh");
    assert_eq!(second.authorization, None);
    assert!(second.body.contains(&token("old_refresh")));
    let third = receiver.recv().expect("retried request");
    assert_eq!(third.path, "/catalog.find");
    assert_eq!(
        third.authorization.as_deref(),
        Some(format!("Bearer {}", token("new_access"))).as_deref()
    );

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

    let (status, code) =
        operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!((status, code.as_str()), (409, "out_of_stock"));

    let (status, code) =
        operation_status_and_code(client.invoke("auth.refresh", &json!({})).unwrap_err());
    assert_eq!((status, code.as_str()), (401, "invalid_token"));

    let (status, code) =
        operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err());
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

    let (status, code) =
        operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err());
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
            _operation: &mut dyn FnMut(
                SessionCredentials,
            ) -> Result<SessionCredentials, ClientError>,
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

    let value = client
        .invoke("catalog.find", &json!({}))
        .expect("call succeeds");
    assert_eq!(value, json!({ "ok": true }));
    assert_eq!(receiver.recv().expect("recorded").path, "/catalog.find");
    assert_eq!(receiver.recv().expect("recorded").path, "/catalog.find");
}

#[test]
fn single_flight_rotates_once_for_concurrent_callers() {
    let originals = Barrier::new(2);
    let (arrived, arrival) = std::sync::mpsc::channel();
    let (release, held) = std::sync::mpsc::channel();
    let held = Mutex::new(held);
    let (joined_sender, joined) = std::sync::mpsc::channel();
    let (origin, receiver) = serve_with(
        &[
            response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
            response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
            response(
                "HTTP/1.1 200 OK",
                &refresh_body("new_access", "new_refresh"),
            ),
            response("HTTP/1.1 200 OK", "{\"which\":1}"),
            response("HTTP/1.1 200 OK", "{\"which\":2}"),
        ],
        move |index| {
            if index < 2 {
                originals.wait();
            }
            if index == 2 {
                arrived.send(()).unwrap();
                held.lock().unwrap().recv().unwrap();
            }
        },
    );
    let store = MemoryStore::new(&origin, credentials("old_access", "old_refresh"));
    client::observe_refresh_joins(&(store.clone() as Arc<dyn SessionStore>), joined_sender);
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
    arrival
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    joined
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    release.send(()).unwrap();
    let first_value = first.join().expect("first thread").expect("first result");
    let second_value = second
        .join()
        .expect("second thread")
        .expect("second result");
    let mut results = vec![
        first_value
            .get("which")
            .and_then(serde_json::Value::as_i64)
            .expect("which"),
        second_value
            .get("which")
            .and_then(serde_json::Value::as_i64)
            .expect("which"),
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
    let originals = Barrier::new(2);
    let (arrived, arrival) = std::sync::mpsc::channel();
    let (release, held) = std::sync::mpsc::channel();
    let held = Mutex::new(held);
    let (joined_sender, joined) = std::sync::mpsc::channel();
    let (origin, receiver) = serve_with(
        &[
            response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
            response("HTTP/1.1 401 Unauthorized", "{\"error\":\"invalid_token\"}"),
            response(
                "HTTP/1.1 200 OK",
                &refresh_body("new_access", "new_refresh"),
            ),
            response("HTTP/1.1 200 OK", "{\"which\":1}"),
            response("HTTP/1.1 200 OK", "{\"which\":2}"),
        ],
        move |index| {
            if index < 2 {
                originals.wait();
            }
            if index == 2 {
                arrived.send(()).unwrap();
                held.lock().unwrap().recv().unwrap();
            }
        },
    );
    let store = MemoryStore::new(&origin, credentials("old_access", "old_refresh"));
    client::observe_refresh_joins(&(store.clone() as Arc<dyn SessionStore>), joined_sender);
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
    arrival
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    joined
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    release.send(()).unwrap();
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
    let store = MemoryStore::new(
        "https://elsewhere.example.com",
        credentials("access", "refresh"),
    );
    let client =
        Client::with_timeout(&origin, std::time::Duration::from_secs(10)).expect("valid origin");
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

#[test]
fn unknown_refresh_blocks_later_calls_on_the_same_store() {
    for (name, reply, save_failure) in [
        ("disconnect", String::new(), None),
        (
            "truncated-401",
            response("HTTP/1.1 401 Unauthorized", "{}")
                .replace("content-length: 2", "content-length: 100"),
            None,
        ),
        ("non-json", response("HTTP/1.1 200 OK", "not JSON"), None),
        (
            "malformed-401",
            response("HTTP/1.1 401 Unauthorized", "{}"),
            None,
        ),
        (
            "non-json-401",
            response("HTTP/1.1 401 Unauthorized", "not JSON"),
            None,
        ),
        (
            "rate-limited",
            response(
                "HTTP/1.1 429 Too Many Requests",
                r#"{"error":"rate_limited"}"#,
            ),
            None,
        ),
        (
            "server-error",
            response(
                "HTTP/1.1 500 Internal Server Error",
                r#"{"error":"internal_error"}"#,
            ),
            None,
        ),
        (
            "invalid-credentials",
            response("HTTP/1.1 200 OK", "{}"),
            None,
        ),
        (
            "save-failure",
            response(
                "HTTP/1.1 200 OK",
                &refresh_body("rotated", "rotated_refresh"),
            ),
            Some(ClientError::Protocol("could not save session".into())),
        ),
        (
            "save-401",
            response(
                "HTTP/1.1 200 OK",
                &refresh_body("rotated", "rotated_refresh"),
            ),
            Some(ClientError::Operation(client::OperationError {
                code: "invalid_token".into(),
                status: 401,
            })),
        ),
    ] {
        let (origin, receiver) = serve(&[
            response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
            reply,
            response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
            response("HTTP/1.1 200 OK", r#"{"ok":true}"#),
        ]);
        let initial = credentials(
            &format!("old_access_{name}"),
            &format!("old_refresh_{name}"),
        );
        let store = Arc::new(MemoryStore {
            origin: origin.clone(),
            state: Mutex::new(Some(initial.clone())),
            save_failure,
            ..MemoryStore::default()
        });
        let client = Client::new(&origin)
            .unwrap()
            .with_session(store.clone())
            .unwrap();
        assert!(client.invoke("catalog.find", &json!({})).is_err(), "{name}");
        let later = Client::new(&origin)
            .unwrap()
            .with_session(store.clone())
            .unwrap();
        let error = later.invoke("catalog.find", &json!({})).unwrap_err();
        assert_eq!(
            operation_status_and_code(error),
            (401, "invalid_token".into()),
            "{name}"
        );
        assert_eq!(store.refresh_calls.load(Ordering::SeqCst), 1, "{name}");
        assert!(
            store.current() == initial,
            "{name}: credentials must remain"
        );
        assert!(store.cleared.lock().unwrap().is_empty(), "{name}");

        *store.state.lock().unwrap() = Some(credentials("new_login", "new_login_refresh"));
        assert_eq!(
            later.invoke("catalog.find", &json!({})).unwrap(),
            json!({"ok":true})
        );
        let paths: Vec<_> = (0..4).map(|_| receiver.recv().unwrap().path).collect();
        assert_eq!(
            paths,
            [
                "/catalog.find",
                "/auth.refresh",
                "/catalog.find",
                "/catalog.find"
            ]
        );
    }
}

#[test]
fn timed_out_refresh_is_not_automatically_sent_again() {
    let (release, held) = std::sync::mpsc::channel();
    let held = Mutex::new(held);
    let (origin, receiver) = serve_with(
        &[
            response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
            response(
                "HTTP/1.1 200 OK",
                &refresh_body("rotated", "rotated_refresh"),
            ),
            response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
        ],
        move |index| {
            if index == 1 {
                held.lock().unwrap().recv().unwrap();
            }
        },
    );
    let store = MemoryStore::new(&origin, credentials("old_access", "old_refresh"));
    let client = Client::with_timeout(&origin, std::time::Duration::from_millis(100))
        .unwrap()
        .with_session(store.clone())
        .unwrap();
    assert_safe_protocol(
        &client.invoke("catalog.find", &json!({})).unwrap_err(),
        "Could not complete the request. Check your connection and confirm the operation outcome before trying again.",
    );
    release.send(()).unwrap();
    assert_eq!(
        operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err()),
        (401, "invalid_token".into())
    );
    assert_eq!(store.refresh_calls.load(Ordering::SeqCst), 1);
    let paths: Vec<_> = (0..3).map(|_| receiver.recv().unwrap().path).collect();
    assert_eq!(paths, ["/catalog.find", "/auth.refresh", "/catalog.find"]);
}

#[test]
fn only_valid_401_error_envelopes_clear_expected_credentials() {
    for (index, body) in [
        r#"{"error":"invalid_response"}"#,
        r#"{"error":"invalid_token"}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let (origin, receiver) = serve(&[
            response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
            response("HTTP/1.1 401 Unauthorized", body),
        ]);
        let expected = credentials(
            &format!("old_access_{index}"),
            &format!("old_refresh_{index}"),
        );
        let store = MemoryStore::new(&origin, expected.clone());
        let client = Client::new(&origin)
            .unwrap()
            .with_session(store.clone())
            .unwrap();
        let (status, code) =
            operation_status_and_code(client.invoke("catalog.find", &json!({})).unwrap_err());
        assert_eq!(status, 401);
        assert_eq!(
            code,
            if body.contains("invalid_token") {
                "invalid_token"
            } else {
                "invalid_response"
            }
        );
        assert!(store.state.lock().unwrap().is_none());
        assert!(store.cleared.lock().unwrap().as_slice() == [expected]);
        assert_eq!(receiver.recv().unwrap().path, "/catalog.find");
        assert_eq!(receiver.recv().unwrap().path, "/auth.refresh");
    }
}

#[test]
fn stale_refresh_failure_preserves_new_login() {
    for (index, reply) in [
        response("HTTP/1.1 401 Unauthorized", "{}"),
        response("HTTP/1.1 200 OK", "{}"),
    ]
    .into_iter()
    .enumerate()
    {
        let (arrived, arrival) = std::sync::mpsc::channel();
        let (release, held) = std::sync::mpsc::channel();
        let held = Mutex::new(held);
        let (origin, receiver) = serve_with(
            &[
                response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
                reply,
                response("HTTP/1.1 200 OK", r#"{"ok":true}"#),
            ],
            move |index| {
                if index == 1 {
                    arrived.send(()).unwrap();
                    held.lock().unwrap().recv().unwrap();
                }
            },
        );
        let store = MemoryStore::new(
            &origin,
            credentials(
                &format!("old_access_{index}"),
                &format!("old_refresh_{index}"),
            ),
        );
        let client = Client::new(&origin)
            .unwrap()
            .with_session(store.clone())
            .unwrap();
        let first = client.clone();
        let call = std::thread::spawn(move || first.invoke("catalog.find", &json!({})));
        arrival
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let login = credentials("new_login", "new_login_refresh");
        *store.state.lock().unwrap() = Some(login.clone());
        release.send(()).unwrap();
        assert!(call.join().unwrap().is_err());
        assert!(store.current() == login);
        assert_eq!(
            client.invoke("catalog.find", &json!({})).unwrap(),
            json!({"ok":true})
        );
        assert_eq!(receiver.recv().unwrap().path, "/catalog.find");
        assert_eq!(receiver.recv().unwrap().path, "/auth.refresh");
        assert_eq!(receiver.recv().unwrap().path, "/catalog.find");
        assert_eq!(store.refresh_calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn reopened_store_cannot_reuse_an_uncertain_refresh_token() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
        String::new(),
        response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
    ]);
    let initial = credentials("old_access", "old_refresh");
    let first_store = MemoryStore::new(&origin, initial.clone());
    let first = Client::new(&origin)
        .unwrap()
        .with_session(first_store)
        .unwrap();
    assert!(first.invoke("catalog.find", &json!({})).is_err());
    drop(first);
    let reopened = MemoryStore::new(&origin, initial);
    let later = Client::new(&origin)
        .unwrap()
        .with_session(reopened.clone())
        .unwrap();
    assert_eq!(
        operation_status_and_code(later.invoke("catalog.find", &json!({})).unwrap_err()),
        (401, "invalid_token".into())
    );
    assert_eq!(receiver.recv().unwrap().path, "/catalog.find");
    assert_eq!(receiver.recv().unwrap().path, "/auth.refresh");
    assert_eq!(receiver.recv().unwrap().path, "/catalog.find");
}

#[test]
fn token_stays_blocked_until_store_persistence_is_confirmed() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
        response(
            "HTTP/1.1 200 OK",
            &refresh_body("rotated", "rotated_refresh"),
        ),
        response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
        response("HTTP/1.1 200 OK", r#"{"ok":true}"#),
    ]);
    let initial = credentials("old_access", "old_refresh");
    let (arrived, arrival) = std::sync::mpsc::channel();
    let release = Arc::new(Barrier::new(2));
    let store = Arc::new(MemoryStore {
        origin: origin.clone(),
        state: Mutex::new(Some(initial.clone())),
        save_barrier: Some((arrived, release.clone())),
        ..MemoryStore::default()
    });
    let first = Client::new(&origin)
        .unwrap()
        .with_session(store.clone())
        .unwrap();
    let (done, completed) = std::sync::mpsc::channel();
    let call =
        std::thread::spawn(move || done.send(first.invoke("catalog.find", &json!({}))).unwrap());
    arrival
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let other = MemoryStore::new(&origin, initial);
    let later = Client::new(&origin).unwrap().with_session(other).unwrap();
    assert_eq!(
        operation_status_and_code(later.invoke("catalog.find", &json!({})).unwrap_err()),
        (401, "invalid_token".into())
    );
    release.wait();
    assert_eq!(
        completed
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .unwrap(),
        json!({"ok":true})
    );
    call.join().unwrap();
    assert_eq!(store.refresh_calls.load(Ordering::SeqCst), 1);
    let paths: Vec<_> = (0..4).map(|_| receiver.recv().unwrap().path).collect();
    assert_eq!(
        paths,
        [
            "/catalog.find",
            "/auth.refresh",
            "/catalog.find",
            "/catalog.find"
        ]
    );
}

#[test]
fn debug_credentials_hide_tokens() {
    let initial = credentials("old_access", "old_refresh");
    let debug = format!("{initial:?}");
    assert!(!debug.contains(&initial.access_token));
    assert!(!debug.contains(&initial.refresh_token));
}

#[test]
fn store_errors_hide_tokens() {
    let initial = credentials("old_access", "old_refresh");
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
        response(
            "HTTP/1.1 200 OK",
            &refresh_body("rotated", "rotated_refresh"),
        ),
    ]);
    let store = Arc::new(MemoryStore {
        origin: origin.clone(),
        save_failure: Some(ClientError::Protocol(format!(
            "storage failed: {}",
            initial.refresh_token
        ))),
        state: Mutex::new(Some(initial)),
        ..MemoryStore::default()
    });
    let client = Client::new(&origin).unwrap().with_session(store).unwrap();
    let error = client.invoke("catalog.find", &json!({})).unwrap_err();
    assert!(error.to_string() == "session refresh failed");
    assert_eq!(receiver.recv().unwrap().path, "/catalog.find");
    assert_eq!(receiver.recv().unwrap().path, "/auth.refresh");
}

fn panicking_store_notifies_waiters(panic_refresh: bool) {
    struct PanicStore {
        inner: Arc<MemoryStore>,
        panic_refresh: bool,
        arrived: std::sync::mpsc::Sender<()>,
        release: Arc<Barrier>,
    }
    impl SessionStore for PanicStore {
        fn bound_origin(&self) -> String {
            self.inner.bound_origin()
        }
        fn credentials(&self) -> SessionCredentials {
            self.inner.credentials()
        }
        fn refresh(
            &self,
            operation: &mut dyn FnMut(
                SessionCredentials,
            ) -> Result<SessionCredentials, ClientError>,
        ) -> Result<SessionCredentials, ClientError> {
            if self.panic_refresh {
                self.arrived.send(()).unwrap();
                self.release.wait();
                panic!("intentional refresh panic");
            }
            self.inner.refresh(operation)
        }
        fn clear(&self, _expected: &SessionCredentials) {
            self.arrived.send(()).unwrap();
            self.release.wait();
            panic!("intentional clear panic");
        }
    }
    let mut replies =
        vec![response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#); 4];
    if !panic_refresh {
        replies.push(replies[0].clone());
    }
    let (origin, receiver) = serve(&replies);
    let (arrived, arrival) = std::sync::mpsc::channel();
    let release = Arc::new(Barrier::new(2));
    let store: Arc<dyn SessionStore> = Arc::new(PanicStore {
        inner: MemoryStore::new(&origin, credentials("old_access", "old_refresh")),
        panic_refresh,
        arrived,
        release: release.clone(),
    });
    let (joined_sender, joined) = std::sync::mpsc::channel();
    client::observe_refresh_joins(&store, joined_sender);
    let client = Client::new(&origin).unwrap().with_session(store).unwrap();
    let (done, results) = std::sync::mpsc::channel();
    let spawn = |is_leader| {
        let client = client.clone();
        let done = done.clone();
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.invoke("catalog.find", &json!({}))
            }))
            .map_err(|_| ());
            done.send((is_leader, outcome)).unwrap();
        })
    };
    let leader = spawn(true);
    arrival
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    let waiters = [spawn(false), spawn(false)];
    for _ in 0..2 {
        joined
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }
    release.wait();
    for _ in 0..3 {
        let (is_leader, outcome) = results
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("flight must finish");
        assert!(outcome.is_ok(), "SDK must recover store panic");
        let error = outcome.unwrap().expect_err("refresh must fail");
        if is_leader {
            assert!(
                matches!(error, ClientError::Protocol(message) if message == "session refresh failed")
            );
        } else {
            assert_eq!(
                operation_status_and_code(error),
                (401, "invalid_token".into())
            );
        }
    }
    leader.join().unwrap();
    for waiter in waiters {
        waiter.join().unwrap();
    }
    let later = spawn(false);
    let (_, outcome) = results
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("later call must finish");
    assert_eq!(
        operation_status_and_code(outcome.unwrap().unwrap_err()),
        (401, "invalid_token".into())
    );
    later.join().unwrap();
    let paths: Vec<_> = (0..replies.len())
        .map(|_| receiver.recv().unwrap().path)
        .collect();
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.as_str() == "/auth.refresh")
            .count(),
        usize::from(!panic_refresh)
    );
}

#[test]
fn refresh_panic_notifies_waiters_and_blocks_later_calls() {
    panicking_store_notifies_waiters(true);
}

#[test]
fn clear_panic_notifies_waiters_and_blocks_later_calls() {
    panicking_store_notifies_waiters(false);
}
