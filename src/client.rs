//! Shared HTTP transport and session runtime behind generated Rust clients.
//!
//! The wire contract is one JSON envelope per operation:
//! `POST {origin}/{service.operation}` with an optional opaque bearer token.
//! Only HTTPS and loopback HTTP origins are accepted, redirects are rejected,
//! requests and responses are bounded, and only invalid sessions trigger a
//! single-flight refresh followed by exactly one retry of the original call.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Read;
use std::net::Ipv4Addr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;
use std::sync::Weak;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_BYTES: usize = 4 << 20;
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const REFRESH_OPERATION: &str = "auth.refresh";

#[cfg(feature = "conformance")]
#[path = "client/conformance.rs"]
#[doc(hidden)]
pub mod conformance;

/// A server-reported operation failure with its error code and HTTP status.
#[derive(Clone, Debug)]
pub struct OperationError {
    pub code: String,
    pub status: u16,
}

impl fmt::Display for OperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "operation failed ({}, HTTP {})",
            self.code, self.status
        )
    }
}

/// Client failures: local protocol and usage problems, and server-reported
/// operation errors that preserve the wire error code and HTTP status.
#[derive(Clone, Debug)]
pub enum ClientError {
    /// The request could not be built, bounded, or decoded.
    Protocol(String),
    /// The server answered with an operation error code and HTTP status.
    Operation(OperationError),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Protocol(message) => write!(formatter, "{message}"),
            ClientError::Operation(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// The rotating credential bundle a session store persists.
#[derive(Clone, Deserialize, PartialEq)]
pub struct SessionCredentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub refresh_expires_at: String,
    pub user_id: String,
    pub session_id: String,
}

impl fmt::Debug for SessionCredentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCredentials")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .finish()
    }
}

/// Caller-owned session credential storage. The SDK never writes credentials
/// to disk itself; implementations decide where sessions persist and declare
/// the one origin the client may ever send their credentials to.
pub trait SessionStore: Send + Sync + 'static {
    /// Returns the deployment origin these credentials are bound to. There is
    /// no default: a store that cannot name its origin cannot be attached.
    fn bound_origin(&self) -> String;
    /// Returns the currently stored credentials.
    fn credentials(&self) -> SessionCredentials;
    /// Rotates credentials through `operation`; the store persists and returns
    /// the credentials it accepted.
    /// Custom stores must preserve concurrent replacement or deletion: compare
    /// the pre-refresh record and save atomically after the callback, without
    /// holding the storage lock during network activity.
    /// Panic recovery requires unwinding; abort builds terminate, and the
    /// caller's panic hook still runs before recovery and may expose its payload.
    fn refresh(
        &self,
        operation: &mut dyn FnMut(SessionCredentials) -> Result<SessionCredentials, ClientError>,
    ) -> Result<SessionCredentials, ClientError>;
    /// Clears the stored credentials only when they still equal `expected`.
    /// Custom stores must compare and delete atomically under the same lock.
    fn clear(&self, expected: &SessionCredentials);
}

/// An origin-bound session store that keeps credentials in process memory.
pub struct MemorySessionStore {
    origin: String,
    credentials: Mutex<Option<SessionCredentials>>,
}

impl MemorySessionStore {
    /// Creates a store for one validated origin and credential pair.
    pub fn new(origin: &str, credentials: Option<SessionCredentials>) -> Result<Self, ClientError> {
        let store = Self {
            origin: validate_origin(origin)?,
            credentials: Mutex::new(None),
        };
        if let Some(credentials) = credentials {
            store.write(credentials)?;
        }
        Ok(store)
    }

    /// Returns the stored record, or None after it has been cleared.
    pub fn read(&self) -> Option<SessionCredentials> {
        self.credentials.lock().expect("session store").clone()
    }

    /// Replaces the current record after validating its credential pair.
    pub fn write(&self, credentials: SessionCredentials) -> Result<(), ClientError> {
        if !valid_token(&credentials.access_token) || !valid_token(&credentials.refresh_token) {
            return Err(ClientError::Protocol("invalid session credential".into()));
        }
        *self.credentials.lock().expect("session store") = Some(credentials);
        Ok(())
    }

    /// Atomically clears only the expected record and returns whether it was removed.
    pub fn clear(&self, expected: &SessionCredentials) -> bool {
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::SessionClearing);
        let mut current = self.credentials.lock().expect("session store");
        let matches = current.as_ref() == Some(expected);
        #[cfg(all(test, feature = "conformance"))]
        conformance::emit(conformance::Event::SessionClearCompared);
        if matches {
            current.take();
            true
        } else {
            false
        }
    }
}

impl SessionStore for MemorySessionStore {
    fn bound_origin(&self) -> String {
        self.origin.clone()
    }
    fn credentials(&self) -> SessionCredentials {
        self.read().unwrap_or_else(|| SessionCredentials {
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
        operation: &mut dyn FnMut(SessionCredentials) -> Result<SessionCredentials, ClientError>,
    ) -> Result<SessionCredentials, ClientError> {
        let expected = self.read().ok_or_else(session_refresh_failed)?;
        let refreshed = operation(expected.clone())?;
        if !valid_token(&refreshed.access_token) || !valid_token(&refreshed.refresh_token) {
            return Err(ClientError::Protocol("invalid session credential".into()));
        }
        let mut current = self.credentials.lock().expect("session store");
        if current.as_ref() != Some(&expected) {
            return Err(session_refresh_failed());
        }
        *current = Some(refreshed.clone());
        drop(current);
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::SessionSaved);
        Ok(refreshed)
    }
    fn clear(&self, expected: &SessionCredentials) {
        self.clear(expected);
    }
}

/// Shared client runtime behind generated Rust SDKs.
#[derive(Clone)]
pub struct Client {
    agent: ureq::Agent,
    origin: String,
    bearer: Option<String>,
    session: Option<Arc<dyn SessionStore>>,
}

impl Client {
    /// Builds a client for a fixed HTTPS or loopback HTTP origin.
    pub fn new(origin: &str) -> Result<Self, ClientError> {
        Self::with_timeout(origin, DEFAULT_TIMEOUT)
    }

    /// Builds a client with an explicit finite timeout for every request.
    pub fn with_timeout(origin: &str, timeout: Duration) -> Result<Self, ClientError> {
        if timeout.is_zero() {
            return Err(ClientError::Protocol(
                "operation timeout must be positive".into(),
            ));
        }
        let origin = validate_origin(origin)?;
        let config = ureq::config::Config::builder()
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build();
        #[cfg(feature = "conformance")]
        let agent = conformance::agent(config);
        #[cfg(not(feature = "conformance"))]
        let agent: ureq::Agent = config.into();
        Ok(Self {
            agent,
            origin,
            bearer: None,
            session: None,
        })
    }

    /// Returns the deployment origin used by this client.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Returns a copy that sends the given bearer token and no session store.
    pub fn with_bearer(&self, token: &str) -> Result<Self, ClientError> {
        if !valid_token(token) {
            return Err(ClientError::Protocol("invalid access token".into()));
        }
        let mut copy = self.clone();
        copy.bearer = Some(token.to_owned());
        copy.session = None;
        Ok(copy)
    }

    /// Returns a copy that authenticates through the session store and
    /// refreshes invalid credentials once per operation call.
    pub fn with_session(&self, store: Arc<dyn SessionStore>) -> Result<Self, ClientError> {
        let credentials = store.credentials();
        self.guard_store_credentials(&store, &credentials)?;
        let mut copy = self.clone();
        copy.bearer = Some(credentials.access_token);
        copy.session = Some(store);
        Ok(copy)
    }

    /// Invokes one declared operation and returns the JSON response value.
    pub fn invoke(&self, operation: &str, input: &Value) -> Result<Value, ClientError> {
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::Entered);
        let Some(store) = self.session.as_ref() else {
            return self.invoke_once(operation, input, self.bearer.as_deref(), None);
        };
        let credentials = store.credentials();
        self.guard_store_credentials(store, &credentials)?;
        let token = if operation == REFRESH_OPERATION {
            None
        } else {
            Some(credentials.access_token.clone())
        };
        let result = self.invoke_once(operation, input, token.as_deref(), None);
        match result {
            Err(ClientError::Operation(OperationError { code, status: 401 }))
                if operation != REFRESH_OPERATION && code == "invalid_token" =>
            {
                #[cfg(feature = "conformance")]
                conformance::emit(conformance::Event::OriginalRejected {
                    access_token: credentials.access_token.clone(),
                });
                let credentials = self.refresh_session(store, &credentials.access_token)?;
                self.invoke_once(operation, input, Some(&credentials.access_token), None)
            }
            other => other,
        }
    }

    fn refresh_session(
        &self,
        store: &Arc<dyn SessionStore>,
        failed_access: &str,
    ) -> Result<SessionCredentials, ClientError> {
        let current = store.credentials();
        self.guard_store_credentials(store, &current)?;
        if current.access_token != failed_access {
            return Ok(current);
        }
        let refresh_token = current.refresh_token.clone();
        let refreshes = store_flights(store);
        let mut leader = false;
        let flight = {
            let mut flights = refreshes.map.lock().expect("refresh flight map");
            match flights.get(&refresh_token) {
                Some(existing) => existing.clone(),
                None => {
                    let flight = Arc::new(Flight::default());
                    flights.insert(refresh_token.clone(), flight.clone());
                    leader = true;
                    flight
                }
            }
        };
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::RefreshParticipation {
            leader,
            refresh_ref: Arc::as_ptr(&flight) as usize,
        });
        #[cfg(test)]
        if !leader && let Some(observer) = refreshes.joined.lock().expect("join observer").as_ref()
        {
            let _ = observer.send(());
        }
        if leader {
            let mut confirmed_rejection = false;
            let outcome = catch_unwind(AssertUnwindSafe(|| {
                self.run_refresh(store, &current, failed_access, &mut confirmed_rejection)
            }))
            .unwrap_or_else(|_| Err(session_refresh_failed()));
            if outcome.is_err() && !confirmed_rejection {
                blocked_refresh_tokens()
                    .lock()
                    .expect("refresh token gate")
                    .insert(Sha256::digest(current.refresh_token.as_bytes()).into());
            }
            // A failed exchange may have consumed the token, including a failed save.
            flight.finish(outcome.clone().map_err(|_| invalid_token_error()));
            if outcome.is_ok() || confirmed_rejection {
                refreshes
                    .map
                    .lock()
                    .expect("refresh flight map")
                    .remove(&refresh_token);
            }
            outcome?;
        }
        flight.result()?;
        let current = store.credentials();
        self.guard_store_credentials(store, &current)?;
        Ok(current)
    }

    fn run_refresh(
        &self,
        store: &Arc<dyn SessionStore>,
        current: &SessionCredentials,
        failed_access: &str,
        confirmed_rejection: &mut bool,
    ) -> Result<String, ClientError> {
        let mut rejected = current.clone();
        let mut refresh_rejected = false;
        let mut callback_error = None;
        let mut attempted_token = None;
        let outcome = store.refresh(&mut |latest| {
            let result = (|| {
                self.guard_store_credentials(store, &latest)?;
                rejected = latest.clone();
                if latest.access_token != failed_access {
                    return Ok(latest);
                }
                let fingerprint = Sha256::digest(latest.refresh_token.as_bytes()).into();
                if !blocked_refresh_tokens()
                    .lock()
                    .expect("refresh token gate")
                    .insert(fingerprint)
                {
                    return Err(invalid_token_error());
                }
                attempted_token = Some(fingerprint);
                let value = self.invoke_once(
                    REFRESH_OPERATION,
                    &serde_json::json!({ "refresh_token": latest.refresh_token }),
                    None,
                    Some(&mut refresh_rejected),
                )?;
                read_credentials(value)
            })();
            if let Err(error) = &result {
                callback_error = Some(error.clone());
            }
            result
        });
        match outcome {
            Ok(refreshed) => {
                self.guard_store_credentials(store, &refreshed)?;
                if let Some(fingerprint) = attempted_token {
                    blocked_refresh_tokens()
                        .lock()
                        .expect("refresh token gate")
                        .remove(&fingerprint);
                }
                Ok(refreshed.access_token)
            }
            Err(_) => {
                if refresh_rejected {
                    store.clear(&rejected);
                    *confirmed_rejection = true;
                    if let Some(fingerprint) = attempted_token {
                        blocked_refresh_tokens()
                            .lock()
                            .expect("refresh token gate")
                            .remove(&fingerprint);
                    }
                }
                Err(callback_error.unwrap_or_else(session_refresh_failed))
            }
        }
    }

    fn invoke_once(
        &self,
        operation: &str,
        input: &Value,
        bearer: Option<&str>,
        rejected: Option<&mut bool>,
    ) -> Result<Value, ClientError> {
        if !valid_operation_name(operation) {
            return Err(ClientError::Protocol("invalid operation name".into()));
        }
        let body = serde_json::to_vec(input)
            .map_err(|_| ClientError::Protocol("invalid operation request".into()))?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(ClientError::Protocol(
                "operation request is too large".into(),
            ));
        }
        let mut request = self
            .agent
            .post(format!("{}/{}", self.origin, operation))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::Sending {
            refresh: operation == REFRESH_OPERATION,
        });
        let response = request
            .send(body)
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let status = response.status().as_u16();
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::Response { status });
        #[cfg(feature = "conformance")]
        let retention = if self.origin.starts_with("http:") {
            Some(256 << 10)
        } else {
            None
        };
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::Transport {
            phase: "headers",
            bytes: 0,
            retained: retention,
        });
        if (300..400).contains(&status) {
            #[cfg(feature = "conformance")]
            conformance::emit(conformance::Event::Transport {
                phase: "cancel-requested",
                bytes: 0,
                retained: Some(0),
            });
            drop(response);
            #[cfg(feature = "conformance")]
            {
                conformance::emit(conformance::Event::Transport {
                    phase: "reader-closed",
                    bytes: 0,
                    retained: Some(0),
                });
                conformance::emit(conformance::Event::ResponseComplete);
            }
            return Err(ClientError::Operation(OperationError {
                code: "redirect_not_allowed".into(),
                status,
            }));
        }
        let reader = response.into_body().into_reader();
        let mut data = Vec::new();
        let mut reader = reader.take((MAX_RESPONSE_BYTES + 1) as u64);
        let result = read_response(&mut reader, &mut data);
        #[cfg(feature = "conformance")]
        if result.is_err() || data.len() > MAX_RESPONSE_BYTES {
            conformance::emit(conformance::Event::Transport {
                phase: "cancel-requested",
                bytes: 0,
                retained: Some(data.capacity()),
            });
        }
        drop(reader);
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::Transport {
            phase: "reader-closed",
            bytes: 0,
            retained: Some(data.capacity()),
        });
        result.map_err(|_| ClientError::Protocol("could not read operation response".into()))?;
        if data.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::Protocol(
                "operation response is too large".into(),
            ));
        }
        #[cfg(feature = "conformance")]
        conformance::emit(conformance::Event::ResponseComplete);
        let value: Value = serde_json::from_slice(&data).map_err(|_| {
            ClientError::Operation(OperationError {
                code: "invalid_response".into(),
                status,
            })
        })?;
        if !(200..300).contains(&status) {
            let code = match value.get("error").and_then(Value::as_str) {
                Some(code) if valid_error_code(code) => {
                    if status == 401
                        && let Some(rejected) = rejected
                    {
                        *rejected = true;
                    }
                    code.to_owned()
                }
                _ => "invalid_response".into(),
            };
            return Err(ClientError::Operation(OperationError { code, status }));
        }
        Ok(value)
    }

    /// Rejects any credential use unless the store is bound to this client's
    /// origin and the opaque tokens are well-formed. This runs before attach
    /// and before every credential read or refresh, so one store can never
    /// send its credentials to any other deployment origin.
    fn guard_store_credentials(
        &self,
        store: &Arc<dyn SessionStore>,
        credentials: &SessionCredentials,
    ) -> Result<(), ClientError> {
        let bound = validate_origin(&store.bound_origin())?;
        if bound != self.origin {
            return Err(ClientError::Protocol(
                "session store is bound to a different origin".into(),
            ));
        }
        if !valid_token(&credentials.access_token) || !valid_token(&credentials.refresh_token) {
            return Err(ClientError::Protocol("invalid session credential".into()));
        }
        Ok(())
    }
}

// Preserve std 1.99's read_to_end growth and initialized-read sizes while exposing Vec capacity.
fn read_response(reader: &mut impl Read, data: &mut Vec<u8>) -> std::io::Result<()> {
    let mut probe = [0; 32];
    let mut max_read = 8192usize;
    let mut initialized = 0;
    loop {
        let length = data.len();
        let result = if data.is_empty() {
            reader.read(&mut probe).map(|count| {
                data.extend_from_slice(&probe[..count]);
                count
            })
        } else {
            if data.capacity() - length < 32 {
                data.try_reserve(32)?;
                initialized = length;
            }
            let amount = if initialized > length + 32 {
                initialized - length
            } else {
                max_read.min(data.capacity() - length)
            };
            // SAFETY: the previous initialized span is still valid after truncation.
            unsafe {
                data.set_len(initialized.min(length + amount).max(length));
            }
            data.resize(length + amount, 0);
            let result = reader.read(&mut data[length..]);
            data.truncate(length + result.as_ref().copied().unwrap_or(0));
            initialized = length + amount;
            result
        };
        let count = match result {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        #[cfg(feature = "conformance")]
        if count > 0 {
            conformance::emit(conformance::Event::Transport {
                phase: "read",
                bytes: count,
                retained: Some(data.capacity()),
            });
            if data.len() > MAX_RESPONSE_BYTES {
                conformance::emit(conformance::Event::Transport {
                    phase: "limit",
                    bytes: 0,
                    retained: Some(data.capacity()),
                });
            }
        }
        if count == 0 {
            return Ok(());
        }
        if count == max_read {
            max_read = max_read.saturating_mul(2);
        }
    }
}

/// Serializes a generated input struct into the transport envelope.
pub fn encode_input<T: serde::Serialize>(input: &T) -> Result<Value, ClientError> {
    serde_json::to_value(input)
        .map_err(|_| ClientError::Protocol("invalid operation request".into()))
}

/// Decodes a response into a generated output struct, rejecting missing,
/// null, or mistyped required fields.
pub fn decode_output<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ClientError> {
    serde_json::from_value(value)
        .map_err(|_| ClientError::Protocol("invalid operation response field".into()))
}

#[derive(Default)]
struct RefreshFlights {
    map: Mutex<HashMap<String, Arc<Flight>>>,
    #[cfg(test)]
    joined: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

// No eviction: another store may still hold a token whose consumption is unknown.
fn blocked_refresh_tokens() -> &'static Mutex<HashSet<[u8; 32]>> {
    static TOKENS: OnceLock<Mutex<HashSet<[u8; 32]>>> = OnceLock::new();
    TOKENS.get_or_init(|| Mutex::new(HashSet::new()))
}

fn invalid_token_error() -> ClientError {
    ClientError::Operation(OperationError {
        code: "invalid_token".into(),
        status: 401,
    })
}

fn session_refresh_failed() -> ClientError {
    ClientError::Protocol("session refresh failed".into())
}

#[cfg(test)]
pub(crate) fn observe_refresh_joins(
    store: &Arc<dyn SessionStore>,
    observer: std::sync::mpsc::Sender<()>,
) {
    *store_flights(store).joined.lock().expect("join observer") = Some(observer);
}

static STORE_FLIGHTS: OnceLock<Mutex<Vec<(Weak<dyn SessionStore>, Arc<RefreshFlights>)>>> =
    OnceLock::new();

/// Returns the refresh flight table bound to one session store, so every
/// client using the same store shares a single-flight rotation.
fn store_flights(store: &Arc<dyn SessionStore>) -> Arc<RefreshFlights> {
    let table = STORE_FLIGHTS.get_or_init(|| Mutex::new(Vec::new()));
    let mut entries = table.lock().expect("store flight table");
    entries.retain(|(known, _)| known.upgrade().is_some());
    for (known, flights) in entries.iter() {
        if Weak::ptr_eq(known, &Arc::downgrade(store)) {
            return flights.clone();
        }
    }
    let flights = Arc::new(RefreshFlights::default());
    entries.push((Arc::downgrade(store), flights.clone()));
    flights
}

struct Flight {
    state: Mutex<Option<Result<String, ClientError>>>,
    signal: Condvar,
}

impl Default for Flight {
    fn default() -> Self {
        Self {
            state: Mutex::new(None),
            signal: Condvar::new(),
        }
    }
}

impl Flight {
    fn finish(&self, result: Result<String, ClientError>) {
        let mut state = self.state.lock().expect("refresh flight state");
        *state = Some(result);
        self.signal.notify_all();
    }

    fn result(&self) -> Result<String, ClientError> {
        let mut state = self.state.lock().expect("refresh flight state");
        while state.is_none() {
            state = self.signal.wait(state).expect("refresh flight state");
        }
        state.as_ref().expect("refresh flight result").clone()
    }
}

fn validate_origin(origin: &str) -> Result<String, ClientError> {
    let invalid = || {
        ClientError::Protocol("operation endpoint must be an HTTPS or loopback HTTP origin".into())
    };
    if origin.contains(['?', '#']) {
        // Reject even empty markers before URI parsing can discard them.
        return Err(invalid());
    }
    let uri: ureq::http::Uri = origin.parse().map_err(|_| invalid())?;
    let scheme = uri.scheme_str().unwrap_or_default();
    let authority = uri.authority().ok_or_else(invalid)?;
    if authority.as_str().contains('@') {
        return Err(invalid());
    }
    let host = authority.host();
    let secure = scheme == "https"
        || (scheme == "http"
            && (host == "[::1]" || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())));
    if !secure || uri.path() != "/" || uri.query().is_some() {
        return Err(invalid());
    }
    Ok(format!("{}://{}", scheme, authority))
}

fn read_credentials(value: Value) -> Result<SessionCredentials, ClientError> {
    let credentials: SessionCredentials = serde_json::from_value(value)
        .map_err(|_| ClientError::Protocol("invalid refresh response".into()))?;
    if !valid_token(&credentials.access_token)
        || !valid_token(&credentials.refresh_token)
        || credentials.expires_at.is_empty()
        || credentials.refresh_expires_at.is_empty()
        || credentials.user_id.is_empty()
        || credentials.session_id.is_empty()
    {
        return Err(ClientError::Protocol("invalid refresh response".into()));
    }
    Ok(credentials)
}

fn valid_token(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_operation_name(operation: &str) -> bool {
    let segments: Vec<&str> = operation.split('.').collect();
    segments.len() == 2 && segments.iter().all(|segment| valid_segment(segment))
}

fn valid_segment(segment: &str) -> bool {
    let mut characters = segment.chars();
    match characters.next() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    characters.all(|character| {
        character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
    })
}

fn valid_error_code(code: &str) -> bool {
    !code.is_empty()
        && code
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase())
}
