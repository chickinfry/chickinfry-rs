use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use chickinfry::client::{ClientError, MemorySessionStore, SessionCredentials, SessionStore};
use serde_json::{Value, json};

use crate::protocol::{self, Error, Result};

#[derive(Default)]
pub struct Credentials {
    refs: Mutex<HashMap<String, String>>,
    observed: Mutex<HashSet<String>>,
}

impl Credentials {
    pub fn load(&self, reader: &mut impl std::io::BufRead) -> Result<()> {
        let mut total = 0;
        while let Some(line) = protocol::bounded_line(reader, 64 << 10)? {
            total += line.len() + 1;
            if total > 1 << 20 {
                return Err(Error::driver("protocol_violation"));
            }
            let value = protocol::json(&line)?;
            protocol::fields(&value, &["ref", "value"], false)?;
            let name = protocol::reference(&value, "ref")?;
            let secret = protocol::string(&value, "value")?;
            if secret.is_empty() {
                return Err(Error::driver("invalid_args"));
            }
            let mut entries = self.refs.lock().unwrap();
            if entries.contains_key(name) {
                return Err(Error::driver("protocol_violation"));
            }
            entries.insert(name.into(), secret.into());
        }
        Ok(())
    }

    pub fn get(&self, reference: &str) -> Result<String> {
        self.refs
            .lock()
            .unwrap()
            .get(reference)
            .cloned()
            .ok_or_else(|| Error::driver("invalid_reference"))
    }

    pub fn find(&self, value: &str) -> Option<String> {
        self.refs
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, secret)| secret.as_str() == value)
            .map(|(name, _)| name.clone())
            .min()
    }

    pub fn contains_secret(&self, value: &str) -> bool {
        self.refs
            .lock()
            .unwrap()
            .values()
            .any(|secret| value.contains(secret))
            || self
                .observed
                .lock()
                .unwrap()
                .iter()
                .any(|secret| value.contains(secret))
    }

    fn observe(&self, credentials: &SessionCredentials) {
        self.observed.lock().unwrap().extend(
            [&credentials.access_token, &credentials.refresh_token]
                .into_iter()
                .filter(|value| !value.is_empty())
                .cloned(),
        );
    }

    pub fn observe_output(&self, output: &Value) {
        for field in ["access_token", "refresh_token"] {
            if let Some(secret) = output
                .get(field)
                .and_then(Value::as_str)
                .filter(|secret| !secret.is_empty())
            {
                self.observed.lock().unwrap().insert(secret.into());
            }
        }
    }

    pub fn register(&self, name: &str, value: &str) -> Result<()> {
        let mut entries = self.refs.lock().unwrap();
        if entries.contains_key(name) {
            return Err(Error::driver("protocol_violation"));
        }
        entries.insert(name.into(), value.into());
        Ok(())
    }

    pub fn sanitize(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.retain(|key, value| {
                    !["access_token", "refresh_token", "password", "credential"]
                        .contains(&key.as_str())
                        && !self.contains_secret(key)
                        && !value.as_str().is_some_and(|v| self.contains_secret(v))
                });
                for value in map.values_mut() {
                    self.sanitize(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.sanitize(value);
                }
            }
            Value::String(v) if self.contains_secret(v) => *value = Value::Null,
            _ => {}
        }
    }
}

#[derive(Default)]
struct State {
    revision: u64,
    clear_attempts: Vec<Value>,
}

pub struct Store {
    state: Mutex<State>,
    runtime: MemorySessionStore,
    origin: String,
    refs: Arc<Credentials>,
}

thread_local! {
    static CALL_ID: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

pub fn with_call<T>(id: &str, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<String>);
    impl Drop for Reset {
        fn drop(&mut self) {
            CALL_ID.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _reset = Reset(CALL_ID.with(|slot| slot.replace(Some(id.into()))));
    f()
}

impl Store {
    pub fn new(refs: Arc<Credentials>, origin: &str) -> Result<Self> {
        Ok(Self {
            state: Mutex::new(State {
                revision: 1,
                ..State::default()
            }),
            runtime: MemorySessionStore::new(origin, None)
                .map_err(|_| Error::driver("invalid_args"))?,
            origin: origin.into(),
            refs,
        })
    }

    pub fn write(
        &self,
        record: &str,
        access: &str,
        refresh: &str,
        origin: Option<&str>,
    ) -> Result<Value> {
        let mut record = protocol::json(self.refs.get(record)?.as_bytes())
            .map_err(|_| Error::driver("invalid_args"))?;
        let fields = [
            "origin",
            "access_token",
            "refresh_token",
            "expires_at",
            "refresh_expires_at",
            "user_id",
            "session_id",
        ];
        protocol::fields(&record, &fields, false).map_err(|_| Error::driver("invalid_args"))?;
        for field in fields {
            if protocol::string(&record, field)?.is_empty() {
                return Err(Error::driver("invalid_args"));
            }
        }
        let record_origin = protocol::string(&record, "origin")?.to_owned();
        if origin.is_some_and(|origin| origin != record_origin) {
            return Err(Error::driver("invalid_args"));
        }
        record.as_object_mut().unwrap().remove("origin");
        let value: SessionCredentials =
            serde_json::from_value(record).map_err(|_| Error::driver("invalid_args"))?;
        if value.access_token != self.refs.get(access)?
            || value.refresh_token != self.refs.get(refresh)?
        {
            return Err(Error::driver("invalid_args"));
        }
        let mut state = self.state.lock().unwrap();
        if self.origin != record_origin {
            return Err(Error::driver("invalid_args"));
        }
        self.refs.observe(&value);
        self.runtime
            .write(value)
            .map_err(|_| Error::driver("invalid_args"))?;
        state.revision += 1;
        Ok(json!({"revision": state.revision, "accessRef": access, "refreshRef": refresh}))
    }

    pub fn read(&self, trace: bool) -> Result<Value> {
        if trace && !cfg!(all(feature = "sdk", feature = "conformance")) {
            return Err(Error::driver("unimplemented"));
        }
        let state = self.state.lock().unwrap();
        let credentials = self.runtime.read();
        if let Some(credentials) = &credentials
            && (self.refs.find(&credentials.access_token).is_none()
                || self.refs.find(&credentials.refresh_token).is_none())
        {
            return Err(Error::driver("invalid_reference"));
        }
        let mut output = json!({
            "present": credentials.is_some(), "revision": state.revision,
            "accessRef": credentials.as_ref().and_then(|v| self.refs.find(&v.access_token)),
            "refreshRef": credentials.as_ref().and_then(|v| self.refs.find(&v.refresh_token)),
        });
        if trace {
            output["clearAttempts"] = json!(state.clear_attempts);
        }
        Ok(output)
    }
}

impl SessionStore for Store {
    fn bound_origin(&self) -> String {
        self.runtime.bound_origin()
    }
    fn credentials(&self) -> SessionCredentials {
        let _observation = self.state.lock().unwrap();
        SessionStore::credentials(&self.runtime)
    }
    fn refresh(
        &self,
        operation: &mut dyn FnMut(
            SessionCredentials,
        ) -> std::result::Result<SessionCredentials, ClientError>,
    ) -> std::result::Result<SessionCredentials, ClientError> {
        let mut observation = None;
        let current = self.runtime.refresh(&mut |credentials| {
            let result = operation(credentials);
            // Publish the actual save and its revision in one observation interval.
            if result.is_ok() {
                observation = Some(self.state.lock().unwrap());
            }
            result
        })?;
        let mut state = observation.expect("successful refresh observation");
        self.refs.observe(&current);
        state.revision += 1;
        Ok(current)
    }
    fn clear(&self, expected: &SessionCredentials) {
        let mut state = self.state.lock().unwrap();
        let removed = self.runtime.clear(expected);
        state.revision += u64::from(removed);
        #[cfg(feature = "conformance")]
        CALL_ID.with(|id| {
            state.clear_attempts.push(json!({
                "callId": id.borrow().as_ref(), "expectedAccessRef": self.refs.find(&expected.access_token),
                "expectedRefreshRef": self.refs.find(&expected.refresh_token), "removed": removed,
            }))
        });
    }
}

#[cfg(test)]
#[test]
fn invalid_protected_records_cannot_replace_a_bound_session() {
    let refs = Arc::new(Credentials::default());
    let access = "M".repeat(43);
    let refresh = "N".repeat(43);
    refs.register("access", &access).unwrap();
    refs.register("refresh", &refresh).unwrap();
    let record = json!({"origin":"http://127.0.0.1:9","access_token":access,"refresh_token":refresh,
        "expires_at":"2099-01-01T00:00:00Z","refresh_expires_at":"2099-01-08T00:00:00Z",
        "user_id":"user","session_id":"session"});
    refs.register("record", &record.to_string()).unwrap();
    let store = Store::new(refs.clone(), "http://127.0.0.1:9").unwrap();
    store
        .write("record", "access", "refresh", Some("http://127.0.0.1:9"))
        .unwrap();
    let before = store.read(false).unwrap();
    for (index, (field, value)) in [
        ("origin", json!("http://127.0.0.1:10")),
        ("access_token", json!(refresh)),
        ("refresh_token", Value::Null),
        ("expires_at", json!(7)),
        ("session_id", json!("")),
        ("unknown", json!("field")),
    ]
    .into_iter()
    .enumerate()
    {
        let mut bad = record.clone();
        bad[field] = value;
        let reference = format!("bad-{index}");
        refs.register(&reference, &bad.to_string()).unwrap();
        assert_eq!(
            store
                .write(&reference, "access", "refresh", None)
                .unwrap_err()
                .code
                .as_deref(),
            Some("invalid_args")
        );
        assert_eq!(store.read(false).unwrap(), before);
    }
}

#[cfg(all(test, feature = "conformance"))]
#[test]
fn refresh_storage_and_revision_are_published_as_one_observation() {
    use std::sync::mpsc;
    use std::time::Duration;
    let refs = Arc::new(Credentials::default());
    let mut records = Vec::new();
    for (index, (access, refresh)) in [("B", "C"), ("D", "E"), ("F", "G")].into_iter().enumerate() {
        let (access, refresh) = (access.repeat(43), refresh.repeat(43));
        refs.register(&format!("access-{index}"), &access).unwrap();
        refs.register(&format!("refresh-{index}"), &refresh)
            .unwrap();
        let credentials = SessionCredentials {
            access_token: access,
            refresh_token: refresh,
            expires_at: "2099-01-01T00:00:00Z".into(),
            refresh_expires_at: "2099-01-08T00:00:00Z".into(),
            user_id: "user".into(),
            session_id: "session".into(),
        };
        let record = json!({"origin":"http://127.0.0.1:9", "access_token":credentials.access_token,
            "refresh_token":credentials.refresh_token, "expires_at":credentials.expires_at,
            "refresh_expires_at":credentials.refresh_expires_at, "user_id":credentials.user_id,
            "session_id":credentials.session_id});
        refs.register(&format!("record-{index}"), &record.to_string())
            .unwrap();
        records.push(credentials);
    }
    let store = Arc::new(Store::new(refs, "http://127.0.0.1:9").unwrap());
    store
        .write("record-0", "access-0", "refresh-0", None)
        .unwrap();
    use chickinfry::client::conformance::{self, Event};
    use std::sync::TryLockError;
    let (saved, saved_at) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    let resumed = Mutex::new(resumed);
    let refresh = std::thread::spawn({
        let store = store.clone();
        let current = records[1].clone();
        move || {
            conformance::observe(
                Arc::new({
                    let store = store.clone();
                    move |event| {
                        if matches!(event, Event::SessionSaved) {
                            assert!(
                                matches!(store.state.try_lock(), Err(TryLockError::WouldBlock)),
                                "observation lock must already cover the actual runtime save"
                            );
                            saved.send(()).unwrap();
                            resumed
                                .lock()
                                .unwrap()
                                .recv_timeout(Duration::from_secs(5))
                                .unwrap();
                        }
                    }
                }),
                || store.refresh(&mut |_| Ok(current.clone())),
            )
        }
    });
    saved_at.recv_timeout(Duration::from_secs(5)).unwrap();
    let (entered, entries) = mpsc::channel();
    let read = std::thread::spawn({
        let store = store.clone();
        let entered = entered.clone();
        move || {
            assert!(matches!(
                store.state.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            entered.send(()).unwrap();
            store.read(false).unwrap()
        }
    });
    let write = std::thread::spawn({
        let store = store.clone();
        move || {
            assert!(matches!(
                store.state.try_lock(),
                Err(TryLockError::WouldBlock)
            ));
            entered.send(()).unwrap();
            store
                .write("record-2", "access-2", "refresh-2", None)
                .unwrap()
        }
    });
    for _ in 0..2 {
        entries.recv_timeout(Duration::from_secs(1)).unwrap();
    }
    resume.send(()).unwrap();
    assert!(refresh.join().unwrap().is_ok());
    let read = read.join().unwrap();
    let write = write.join().unwrap();
    assert!(
        read["accessRef"] == "access-1" && read["revision"] == 3
            || read["accessRef"] == "access-2" && read["revision"] == 4
    );
    assert_eq!(write["revision"], 4);
    assert_eq!(store.read(false).unwrap()["accessRef"], "access-2");
}

#[cfg(all(test, feature = "sdk", feature = "conformance"))]
#[test]
fn clearing_trace_uses_the_runtime_decision_after_concurrent_record_replacement() {
    use chickinfry::client::conformance::{self, Event};
    use std::sync::atomic::{AtomicBool, Ordering};
    let refs = Arc::new(Credentials::default());
    let mut records = Vec::new();
    for (index, (access, refresh)) in [("L", "N"), ("M", "O")].into_iter().enumerate() {
        let credentials = SessionCredentials {
            access_token: access.repeat(43),
            refresh_token: refresh.repeat(43),
            expires_at: "2099-01-01T00:00:00Z".into(),
            refresh_expires_at: "2099-01-08T00:00:00Z".into(),
            user_id: "user".into(),
            session_id: "session".into(),
        };
        refs.register(&format!("access-{index}"), &credentials.access_token)
            .unwrap();
        refs.register(&format!("refresh-{index}"), &credentials.refresh_token)
            .unwrap();
        records.push(credentials);
    }
    for initially_expected in [true, false] {
        let store = Arc::new(Store::new(refs.clone(), "http://127.0.0.1:9").unwrap());
        let initial = usize::from(!initially_expected);
        store.runtime.write(records[initial].clone()).unwrap();
        let entered = Arc::new(AtomicBool::new(false));
        conformance::observe(
            Arc::new({
                let store = store.clone();
                let entered = entered.clone();
                let replacement = records[1 - initial].clone();
                move |event| {
                    if matches!(event, Event::SessionClearing) {
                        entered.store(true, Ordering::SeqCst);
                        let store = store.clone();
                        let replacement = replacement.clone();
                        std::thread::spawn(move || store.runtime.write(replacement).unwrap())
                            .join()
                            .unwrap();
                    }
                }
            }),
            || {
                with_call("c:clear", || {
                    SessionStore::clear(store.as_ref(), &records[0])
                })
            },
        );
        assert!(
            entered.load(Ordering::SeqCst),
            "the runtime must make the clearing decision"
        );
        let snapshot = store.read(true).unwrap();
        assert_eq!(
            snapshot["clearAttempts"],
            json!([{"callId":"c:clear","expectedAccessRef":"access-0",
            "expectedRefreshRef":"refresh-0","removed":!initially_expected}])
        );
        assert_eq!(snapshot["present"], initially_expected);
        if initially_expected {
            assert_eq!(snapshot["accessRef"], "access-1");
        }
    }
}
