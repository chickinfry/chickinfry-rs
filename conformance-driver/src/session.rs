use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use chickinfry::client::{ClientError, SessionCredentials, SessionStore};
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

    pub fn register(&self, name: &str, value: &str) -> Result<()> {
        let mut entries = self.refs.lock().unwrap();
        if entries.get(name).is_some_and(|v| v != value) {
            return Err(Error::driver("protocol_violation"));
        }
        entries.entry(name.into()).or_insert_with(|| value.into());
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
    origin: Option<String>,
    credentials: Option<SessionCredentials>,
    revision: u64,
    clear_attempts: Vec<Value>,
    participants: Vec<Value>,
}

pub struct Store {
    state: Mutex<State>,
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
    pub fn new(refs: Arc<Credentials>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            refs,
        }
    }

    pub fn bind(&self, origin: &str) {
        self.state
            .lock()
            .unwrap()
            .origin
            .get_or_insert_with(|| origin.into());
    }

    pub fn write(&self, access: &str, refresh: &str) -> Result<Value> {
        let value = SessionCredentials {
            access_token: self.refs.get(access)?,
            refresh_token: self.refs.get(refresh)?,
            expires_at: String::new(),
            refresh_expires_at: String::new(),
            user_id: String::new(),
            session_id: String::new(),
        };
        let mut state = self.state.lock().unwrap();
        self.refs.observe(&value);
        state.credentials = Some(value);
        state.revision += 1;
        Ok(json!({"revision": state.revision, "accessRef": access, "refreshRef": refresh}))
    }

    pub fn read(&self, trace: bool) -> Result<Value> {
        if trace && !cfg!(all(feature = "sdk", feature = "conformance")) {
            return Err(Error::driver("unimplemented"));
        }
        let state = self.state.lock().unwrap();
        if let Some(credentials) = &state.credentials
            && (self.refs.find(&credentials.access_token).is_none()
                || self.refs.find(&credentials.refresh_token).is_none())
        {
            return Err(Error::driver("invalid_reference"));
        }
        let mut output = json!({
            "present": state.credentials.is_some(), "revision": state.revision,
            "accessRef": state.credentials.as_ref().and_then(|v| self.refs.find(&v.access_token)),
            "refreshRef": state.credentials.as_ref().and_then(|v| self.refs.find(&v.refresh_token)),
        });
        if trace {
            output["clearAttempts"] = json!(state.clear_attempts);
            output["refreshParticipants"] = json!(state.participants);
        }
        Ok(output)
    }

    #[cfg(feature = "conformance")]
    pub fn participation(&self, id: &str, leader: bool, refresh_token: &str) {
        self.state.lock().unwrap().participants.push(
            json!({"callId": id, "leader": leader, "refreshRef": self.refs.find(refresh_token)}),
        );
    }
}

impl SessionStore for Store {
    fn bound_origin(&self) -> String {
        self.state
            .lock()
            .unwrap()
            .origin
            .clone()
            .unwrap_or_default()
    }
    fn credentials(&self) -> SessionCredentials {
        self.state
            .lock()
            .unwrap()
            .credentials
            .clone()
            .unwrap_or_else(|| SessionCredentials {
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: String::new(),
                refresh_expires_at: String::new(),
                user_id: String::new(),
                session_id: String::new(),
            })
    }
    fn refresh(
        &self,
        operation: &mut dyn FnMut(
            SessionCredentials,
        ) -> std::result::Result<SessionCredentials, ClientError>,
    ) -> std::result::Result<SessionCredentials, ClientError> {
        let current = operation(self.credentials())?;
        let mut state = self.state.lock().unwrap();
        self.refs.observe(&current);
        state.credentials = Some(current.clone());
        state.revision += 1;
        Ok(current)
    }
    fn clear(&self, expected: &SessionCredentials) {
        let mut state = self.state.lock().unwrap();
        let removed = state.credentials.as_ref() == Some(expected);
        if removed {
            state.credentials = None;
            state.revision += 1;
        }
        #[cfg(feature = "conformance")]
        CALL_ID.with(|id| {
            state.clear_attempts.push(json!({
                "callId": id.borrow().as_ref(), "accessRef": self.refs.find(&expected.access_token),
                "refreshRef": self.refs.find(&expected.refresh_token), "removed": removed,
            }))
        });
    }
}
