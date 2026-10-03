//! Shared HTTP transport and session runtime behind generated Rust clients.
//!
//! The wire contract is one JSON envelope per operation:
//! `POST {origin}/{service.operation}` with an optional opaque bearer token.
//! Only HTTPS and loopback HTTP origins are accepted, redirects are rejected,
//! requests and responses are bounded, and only invalid sessions trigger a
//! single-flight refresh followed by exactly one retry of the original call.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use std::sync::OnceLock;
use std::sync::Weak;

use serde::Deserialize;
use serde_json::Value;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST_BYTES: usize = 4 << 20;
const MAX_RESPONSE_BYTES: usize = 1 << 20;
const REFRESH_OPERATION: &str = "auth.refresh";

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
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SessionCredentials {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub refresh_expires_at: String,
    pub user_id: String,
    pub session_id: String,
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
    fn refresh(
        &self,
        operation: &mut dyn FnMut(SessionCredentials) -> Result<SessionCredentials, ClientError>,
    ) -> Result<SessionCredentials, ClientError>;
    /// Clears the stored credentials only when they still equal `expected`.
    fn clear(&self, expected: &SessionCredentials);
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
        let agent: ureq::Agent = ureq::config::Config::builder()
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_global(Some(timeout))
            .build()
            .into();
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
        let Some(store) = self.session.as_ref() else {
            return self.invoke_once(operation, input, self.bearer.as_deref());
        };
        let credentials = store.credentials();
        self.guard_store_credentials(store, &credentials)?;
        let token = if operation == REFRESH_OPERATION {
            None
        } else {
            Some(credentials.access_token.clone())
        };
        let result = self.invoke_once(operation, input, token.as_deref());
        match result {
            Err(ClientError::Operation(OperationError { code, status: 401 }))
                if operation != REFRESH_OPERATION && code == "invalid_token" =>
            {
                let credentials = self.refresh_session(store, &credentials.access_token)?;
                self.invoke_once(operation, input, Some(&credentials.access_token))
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
        if leader {
            let outcome = self.run_refresh(store, &current, failed_access);
            flight.finish(outcome);
            refreshes
                .map
                .lock()
                .expect("refresh flight map")
                .remove(&refresh_token);
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
    ) -> Result<String, ClientError> {
        let mut rejected = current.clone();
        let outcome = store.refresh(&mut |latest| {
            self.guard_store_credentials(store, &latest)?;
            rejected = latest.clone();
            if latest.access_token != failed_access {
                return Ok(latest);
            }
            let value = self.invoke_once(
                REFRESH_OPERATION,
                &serde_json::json!({ "refresh_token": latest.refresh_token }),
                None,
            )?;
            read_credentials(value)
        });
        match outcome {
            Ok(refreshed) => Ok(refreshed.access_token),
            Err(error) => {
                if matches!(
                    error,
                    ClientError::Operation(OperationError { status: 401, .. })
                ) {
                    store.clear(&rejected);
                }
                Err(error)
            }
        }
    }

    fn invoke_once(
        &self,
        operation: &str,
        input: &Value,
        bearer: Option<&str>,
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
        let response = request
            .send(body)
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(ClientError::Operation(OperationError {
                code: "redirect_not_allowed".into(),
                status,
            }));
        }
        let reader = response.into_body().into_reader();
        let mut data = Vec::new();
        reader
            .take((MAX_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| ClientError::Protocol("could not read operation response".into()))?;
        if data.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::Protocol(
                "operation response is too large".into(),
            ));
        }
        let value: Value = serde_json::from_slice(&data).map_err(|_| {
            ClientError::Operation(OperationError {
                code: "invalid_response".into(),
                status,
            })
        })?;
        if !(200..300).contains(&status) {
            let code = match value.get("error").and_then(Value::as_str) {
                Some(code) if valid_error_code(code) => code.to_owned(),
                _ => "operation_failed".into(),
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
        ClientError::Protocol(
            "operation endpoint must be an HTTPS or loopback HTTP origin".into(),
        )
    };
    if origin.contains('#') {
        // The URI parser drops fragments instead of rejecting them.
        return Err(invalid());
    }
    let uri: ureq::http::Uri = origin.parse().map_err(|_| invalid())?;
    let scheme = uri.scheme_str().unwrap_or_default();
    let authority = uri.authority().ok_or_else(invalid)?;
    if authority.as_str().contains('@') {
        return Err(invalid());
    }
    let ip: Option<IpAddr> = host_ip(authority.host());
    let secure =
        scheme == "https" || (scheme == "http" && ip.is_some_and(|ip| ip.is_loopback()));
    if !secure || uri.path() != "/" || uri.query().is_some() {
        return Err(invalid());
    }
    Ok(format!("{}://{}", scheme, authority))
}

fn host_ip(host: &str) -> Option<IpAddr> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    unbracketed.parse().ok()
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
    !code.is_empty() && code.bytes().all(|byte| byte == b'_' || byte.is_ascii_lowercase())
}
