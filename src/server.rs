//! Wire protocol and application serving. Semantics mirror the other server
//! languages: POST to one operation path, JSON bodies, bounded requests,
//! opaque bearer tokens, typed error envelopes, and no retry on business
//! failures.

use crate::database::{DatabasePort, TransactionPort};
pub use crate::error_details::FieldError;
use crate::error_details::{valid_error_code, valid_fields, valid_message};
use crate::wasm_bindgen;
use std::sync::atomic::{AtomicU64, Ordering};

mod json;

/// Maximum accepted request body size, shared with the generated SDK limits.
pub const REQUEST_BODY_LIMIT: usize = 4 << 20;

const TOKEN_LIMIT: usize = 4 << 20;

static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Runtime view of one incoming request handed to the generated context.
pub struct RuntimeContext {
    pub rid: u64,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub session: Option<Session>,
    pub database: Option<DatabasePort>,
    secrets: std::collections::BTreeMap<String, String>,
    vault: Vault,
}

/// One declared logical storage, routed per request through the shared host
/// storage port. The customer module never sees binding credentials.
#[derive(Clone)]
pub struct Storage {
    rid: u64,
    name: String,
}

const STORAGE_OBJECT_LIMIT: usize = 4 << 20;

impl Storage {
    pub fn new(rid: u64, name: &str) -> Storage {
        Storage {
            rid,
            name: name.to_string(),
        }
    }

    /// Reads one object. A missing object is None; an unbound logical storage
    /// is service_unavailable and every other failure is operation_failed.
    pub async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, OperationError> {
        match crate::host::storage(self.rid, "get", &self.name, key, None, None).await {
            Ok(crate::host::StorageOutcome::Value(value)) => Ok(value),
            Ok(crate::host::StorageOutcome::Error(code)) => Err(storage_error(&code)),
            Ok(crate::host::StorageOutcome::Written) | Err(_) => Err(OperationError::internal()),
        }
    }

    /// Writes one object with its content type. The public result is void.
    pub async fn put(
        &self,
        key: &str,
        bytes: Vec<u8>,
        content_type: &str,
    ) -> Result<(), OperationError> {
        if bytes.len() > STORAGE_OBJECT_LIMIT {
            return Err(OperationError::internal());
        }
        match crate::host::storage(
            self.rid,
            "put",
            &self.name,
            key,
            Some(&bytes),
            Some(content_type),
        )
        .await
        {
            Ok(crate::host::StorageOutcome::Written) => Ok(()),
            Ok(crate::host::StorageOutcome::Error(code)) => Err(storage_error(&code)),
            Ok(crate::host::StorageOutcome::Value(_)) | Err(_) => Err(OperationError::internal()),
        }
    }
}

/// Publishes realtime events through the shared host realtime port. The
/// engine binding and its credentials stay in the host.
#[derive(Clone)]
pub struct Realtime {
    rid: u64,
}

impl Realtime {
    pub fn new(rid: u64) -> Realtime {
        Realtime { rid }
    }

    /// Publishes one event on a channel and resolves without a result value
    /// once the engine confirmed it. Engine rejections keep their public code
    /// and status; an unconfirmed outcome is realtime_publish_outcome_unknown.
    pub async fn publish<T: serde::Serialize + ?Sized>(
        &self,
        channel: &str,
        payload: &T,
    ) -> Result<(), OperationError> {
        let frame = serde_json::to_value(payload).and_then(|payload| {
            serde_json::to_vec(&serde_json::json!({
                "rid": self.rid,
                "op": "publish",
                "input": { "channel": channel, "payload": payload },
            }))
        });
        let Ok(frame) = frame else {
            return Err(OperationError::internal());
        };
        // A call the host never accepted was not sent, so it is a plain failure.
        match crate::host::realtime(frame).await {
            Ok(reply) => realtime_result(&reply),
            Err(_) => Err(OperationError::internal()),
        }
    }
}

fn realtime_result(reply: &serde_json::Value) -> Result<(), OperationError> {
    let Some(reply) = reply.as_object() else {
        return Err(OperationError::internal());
    };
    match (reply.get("error"), reply.get("status")) {
        (None, None) if reply.is_empty() => Ok(()),
        (Some(serde_json::Value::String(code)), None) if code == "binding_unavailable" => {
            Err(OperationError::from_code("service_unavailable", 503))
        }
        (Some(serde_json::Value::String(code)), Some(status)) if reply.len() == 2 => {
            match status
                .as_u64()
                .and_then(|status| u16::try_from(status).ok())
            {
                Some(status) => Err(OperationError::from_code(code, status)),
                None => Err(OperationError::internal()),
            }
        }
        _ => Err(OperationError::internal()),
    }
}

fn storage_error(code: &str) -> OperationError {
    if code == "service_unavailable" {
        OperationError::from_code("service_unavailable", 503)
    } else {
        OperationError::internal()
    }
}

/// The public log levels shared by every server language. Invalid levels
/// cannot be expressed: the type only offers the four collected levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

#[doc(hidden)]
pub fn log(level: LogLevel, message: &str, fields: Option<&serde_json::Value>) {
    crate::logging::send(level.as_str(), message, fields);
}

/// Project-scoped vault snapshot delivered with the private binding frame.
/// Scope or project mismatches surface as service_unavailable; a secret the
/// snapshot does not carry is operation_failed.
#[derive(Clone)]
pub struct Vault {
    scope: String,
    project: String,
    raw: Option<String>,
}

impl Vault {
    fn from_config(config: &crate::RuntimeConfig) -> Vault {
        Vault {
            scope: config.vault_scope.clone().unwrap_or_default(),
            project: config.project_id.clone().unwrap_or_default(),
            raw: config.vault.clone(),
        }
    }

    pub fn get(&self, secret_name: &str) -> Result<String, OperationError> {
        let values = self.resolve()?;
        values
            .get(secret_name)
            .cloned()
            .ok_or_else(OperationError::internal)
    }

    fn resolve(&self) -> Result<std::collections::BTreeMap<String, String>, OperationError> {
        let unavailable = || OperationError::from_code("service_unavailable", 503);
        let raw = self.raw.as_deref().filter(|value| !value.is_empty());
        if self.scope.is_empty() || self.project.is_empty() {
            return Err(unavailable());
        }
        let parsed: serde_json::Value =
            serde_json::from_str(raw.ok_or_else(unavailable)?).map_err(|_| unavailable())?;
        let object = parsed.as_object().ok_or_else(unavailable)?;
        if object.get("projectId").and_then(serde_json::Value::as_str)
            != Some(self.project.as_str())
        {
            return Err(unavailable());
        }
        if object.get("vault").and_then(serde_json::Value::as_str) != Some(self.scope.as_str()) {
            return Err(unavailable());
        }
        let values = object
            .get("values")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(unavailable)?;
        let mut snapshot = std::collections::BTreeMap::new();
        for (name, value) in values {
            let value = value.as_str().ok_or_else(unavailable)?;
            snapshot.insert(name.clone(), value.to_string());
        }
        Ok(snapshot)
    }
}

impl RuntimeContext {
    #[doc(hidden)]
    pub fn secret(&self, name: &str) -> Result<String, OperationError> {
        self.secrets
            .get(name)
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| OperationError::from_code("service_unavailable", 503))
    }

    pub fn vault(&self) -> Vault {
        self.vault.clone()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The customer-facing request view carried by the generated context.
    pub fn request_view(&self) -> RequestView {
        RequestView {
            method: self.method.clone(),
            path: self.path.clone(),
            headers: self.headers.clone(),
        }
    }

    /// The pooled database port for this request, present when the project
    /// declares a database profile and the engine delivered the binding.
    pub fn database_port(&self) -> Option<DatabasePort> {
        self.database
    }
}

/// The customer-facing view of one request, carried by the generated context.
#[derive(Clone)]
pub struct RequestView {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl RequestView {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One application session verified by the request host.
#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub user: SessionUser,
}

#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionUser {
    pub id: String,
    pub email: String,
}

/// Public operation error with its HTTP status and stable error code.
#[derive(Clone)]
pub struct OperationError {
    pub code: String,
    pub status: u16,
    pub message: Option<String>,
    pub fields: Vec<FieldError>,
    database_code: Option<String>,
}

impl OperationError {
    /// Creates an operation error with explicitly public response details.
    pub fn new(code: &str, status: u16, message: Option<&str>, fields: Vec<FieldError>) -> Self {
        if !valid_error_code(code) || !(400..=599).contains(&status) {
            return Self::internal();
        }
        Self {
            code: code.to_string(),
            status,
            message: message.map(str::to_owned),
            fields,
            database_code: None,
        }
    }

    pub(crate) fn from_code(code: &str, status: u16) -> Self {
        Self::new(code, status, None, Vec::new())
    }

    /// Generic internal failure. Internal details never reach the wire.
    pub fn internal() -> Self {
        Self {
            code: "operation_failed".to_string(),
            status: 500,
            message: None,
            fields: Vec::new(),
            database_code: None,
        }
    }

    pub fn unauthenticated() -> Self {
        Self::from_code("unauthenticated", 401)
    }

    pub fn invalid_token() -> Self {
        Self::from_code("invalid_token", 401)
    }

    pub(crate) fn database(code: String) -> Self {
        Self {
            database_code: Some(code),
            ..Self::internal()
        }
    }

    pub(crate) fn unique_violation(&self) -> bool {
        self.database_code.as_deref() == Some("23505")
    }
}

/// Marker for rejected input shapes; mapped to the shared invalid_input code.
#[derive(Debug)]
pub struct InvalidInputError;

impl std::fmt::Display for InvalidInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid input")
    }
}

impl std::error::Error for InvalidInputError {}

/// Errors a generated dispatch can return.
pub enum DispatchError {
    InvalidInput(InvalidInputError),
    Operation(OperationError),
    Internal,
}

impl From<InvalidInputError> for DispatchError {
    fn from(error: InvalidInputError) -> Self {
        DispatchError::InvalidInput(error)
    }
}

impl From<OperationError> for DispatchError {
    fn from(error: OperationError) -> Self {
        DispatchError::Operation(error)
    }
}

impl serde::de::Error for InvalidInputError {
    fn custom<T: std::fmt::Display>(_message: T) -> Self {
        InvalidInputError
    }
}

/// Implemented by the generated application. The associated context carries
/// the project-owned request context built from RuntimeContext.
#[allow(async_fn_in_trait)]
pub trait Application {
    type Context: ProjectContext;
    /// Whether the declared operations include this operation identifier.
    fn accepts(&self, operation: &str) -> bool;
    #[doc(hidden)]
    fn input_fields(&self, _operation: &str) -> &'static [&'static str] {
        &[]
    }
    /// Whether the project declares a database profile.
    const REQUIRES_DATABASE: bool;
    /// Whether the project declares platform authentication in auth.yml.
    const AUTH_ENABLED: bool;
    const EMAIL_PASSWORD_ENABLED: bool = false;
    /// Successful native refreshes extend the session by this many idle seconds.
    const SESSION_IDLE_TIMEOUT_SECONDS: u64 = 2_592_000;
    /// Maximum seconds since first login; zero disables the absolute limit.
    const SESSION_ABSOLUTE_LIFETIME_SECONDS: u64 = 0;
    const ALLOWED_ORIGINS: &'static [&'static str] = &[];
    fn identity_providers(&self) -> &[Box<dyn crate::auth::IdentityProvider>] {
        &[]
    }
    fn auth_hooks(&self) -> impl crate::auth::UserCreationHooks {
        crate::auth::NoHooks
    }
    async fn invoke(
        &self,
        context: &Self::Context,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, DispatchError>;
}

/// Built by the generated context from the runtime view.
pub trait ProjectContext {
    fn build(runtime: &RuntimeContext) -> Self;
}

/// Reads and validates one operation input object through the generated type.
pub fn read_input<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    _operation: &str,
) -> Result<T, InvalidInputError> {
    serde_json::from_value(value).map_err(|_| InvalidInputError)
}

/// Serializes one handler output value.
pub fn write_output<T: serde::Serialize>(output: T) -> Result<serde_json::Value, DispatchError> {
    serde_json::to_value(output).map_err(|_| DispatchError::Internal)
}

#[derive(serde::Deserialize)]
struct RequestMetadata {
    config: Option<crate::RuntimeConfig>,
    database: Option<bool>,
    id: Option<u64>,
    method: String,
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    auth: Option<HostAuthentication>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAuthentication {
    version: u32,
    #[serde(deserialize_with = "serde::Deserialize::deserialize")]
    session: Option<HostSession>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostSession {
    id: String,
    user: SessionUser,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthHookFrame {
    version: u32,
    hook: AuthHook,
    user: crate::auth::AuthUser,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
enum AuthHook {
    UserCreating,
    UserCreated,
}

struct ResponseEnvelope {
    status: u16,
    body: serde_json::Value,
}

fn error_envelope(status: u16, code: &str) -> ResponseEnvelope {
    operation_error_envelope(OperationError::from_code(code, status), &[])
}

fn operation_error_envelope(error: OperationError, declared: &[&str]) -> ResponseEnvelope {
    if !(400..=599).contains(&error.status) || !valid_error_code(&error.code) {
        return ResponseEnvelope {
            status: 500,
            body: serde_json::json!({"error": "operation_failed"}),
        };
    }
    let mut body = serde_json::json!({ "error": error.code });
    if let Some(message) = error.message.filter(|message| valid_message(message)) {
        body["message"] = serde_json::Value::String(message);
    }
    if error.code == "invalid_input"
        && !error.fields.is_empty()
        && valid_fields(&error.fields, Some(declared))
    {
        body["fields"] = serde_json::json!(error.fields);
    }
    ResponseEnvelope {
        status: error.status,
        body,
    }
}

#[cfg(test)]
mod public_error_tests {
    use super::*;

    #[test]
    fn operation_errors_validate_optional_details_at_the_wire_boundary() {
        let field = |path: &str| FieldError {
            path: path.into(),
            code: "too_large".into(),
        };
        let error = OperationError::new("invalid_input", 422, Some(""), vec![field("quantity")]);
        let response = operation_error_envelope(error, &["quantity"]);
        assert_eq!(response.status, 422);
        assert_eq!(
            response.body,
            serde_json::json!({
                "error": "invalid_input",
                "message": "",
                "fields": [{"path": "quantity", "code": "too_large"}]
            })
        );

        let error = OperationError::new(
            "invalid_input",
            422,
            Some("safe"),
            vec![field("quantity"), field("undeclared")],
        );
        assert_eq!(
            operation_error_envelope(error, &["quantity"]).body,
            serde_json::json!({"error": "invalid_input", "message": "safe"})
        );

        let mut error =
            OperationError::new("invalid_input", 422, Some("safe"), vec![field("quantity")]);
        error.message = Some("bad\nmessage".into());
        assert_eq!(
            operation_error_envelope(error.clone(), &["quantity"]).body,
            serde_json::json!({"error": "invalid_input", "fields": [{"path": "quantity", "code": "too_large"}]})
        );

        error.status = 200;
        error.message = Some("do not reflect".into());
        let response = operation_error_envelope(error, &["quantity"]);
        assert_eq!(response.status, 500);
        assert_eq!(
            response.body,
            serde_json::json!({"error": "operation_failed"})
        );
    }

    #[test]
    fn error_output_validates_mutable_public_members() {
        for (status, code) in [
            (399, "custom"),
            (600, "custom"),
            (200, "custom"),
            (400, "Bad Code"),
            (500, ""),
        ] {
            let response = error_envelope(status, code);
            assert_eq!(response.status, 500);
            assert_eq!(
                response.body,
                serde_json::json!({"error": "operation_failed"})
            );
        }
        for status in [400, 599] {
            let response = error_envelope(status, "custom");
            assert_eq!(response.status, status);
            assert_eq!(response.body, serde_json::json!({"error": "custom"}));
        }
    }
}

fn is_credential_header(name: &str, auth_enabled: bool) -> bool {
    name.eq_ignore_ascii_case("proxy-authorization")
        || auth_enabled
            && ["authorization", "cookie"]
                .iter()
                .any(|header| name.eq_ignore_ascii_case(header))
}

fn validate_application<A: Application>(application: &A) -> Result<(), &'static str> {
    use crate::auth::UserCreationHooks;

    if !A::AUTH_ENABLED
        && (!application.identity_providers().is_empty()
            || application.auth_hooks().is_registered())
    {
        return Err("declare auth in auth.yml");
    }
    Ok(())
}

/// Dispatches a callback from the trusted host entry using its current lease.
#[doc(hidden)]
pub async fn serve_auth_hook<A: Application>(
    application: &A,
    metadata: &[u8],
    rid: u64,
    lease: Option<u64>,
) -> Result<(), OperationError> {
    use crate::auth::UserCreationHooks;

    if !A::AUTH_ENABLED || rid == 0 || metadata.len() > REQUEST_BODY_LIMIT {
        return Err(OperationError::internal());
    }
    let frame: AuthHookFrame =
        serde_json::from_slice(metadata).map_err(|_| OperationError::internal())?;
    let user = &frame.user;
    if frame.version != 1
        || user.id.is_empty()
        || user.email.is_empty()
        || user.created_at.is_empty()
    {
        return Err(OperationError::internal());
    }
    let hooks = application.auth_hooks();
    crate::logging::scope(rid, async {
        match (frame.hook, lease) {
            (AuthHook::UserCreating, Some(lease)) if lease != 0 => hooks
                .creating(TransactionPort::borrowed(rid, lease), user)
                .await
                .map_err(|_| OperationError::from_code("user_creation_failed", 500)),
            (AuthHook::UserCreated, None) => hooks
                .committed(user)
                .await
                .map_err(|_| OperationError::from_code("user_created_effect_failed", 500)),
            _ => Err(OperationError::internal()),
        }
    })
    .await
}

/// Serves one request frame. The engine glue supplies the request metadata and
/// body separately and consumes the response envelope.
pub async fn serve<A: Application>(
    application: A,
    metadata: Vec<u8>,
    body: Vec<u8>,
) -> Result<Vec<u8>, wasm_bindgen::JsValue> {
    validate_application(&application).map_err(wasm_bindgen::JsValue::from_str)?;
    let origin = serde_json::from_slice::<RequestMetadata>(&metadata)
        .ok()
        .and_then(|request| {
            request
                .headers
                .into_iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("origin"))
        })
        .map(|(_, value)| value);
    let envelope = match serve_inner(&application, metadata, body, crate::config()).await {
        Ok(envelope) => envelope,
        Err(status) => error_envelope(status, "operation_failed"),
    };
    let mut headers = serde_json::Map::new();
    if A::AUTH_ENABLED
        && origin
            .as_deref()
            .is_some_and(|origin| A::ALLOWED_ORIGINS.contains(&origin))
    {
        headers.insert(
            "access-control-allow-origin".into(),
            serde_json::json!(origin),
        );
        headers.insert("vary".into(), serde_json::json!("Origin"));
        headers.insert(
            "access-control-allow-methods".into(),
            serde_json::json!("POST"),
        );
        headers.insert(
            "access-control-allow-headers".into(),
            serde_json::json!("content-type, authorization"),
        );
    }
    let response =
        serde_json::json!({ "status": envelope.status, "body": envelope.body, "headers": headers });
    serde_json::to_vec(&response)
        .map_err(|_| wasm_bindgen::JsValue::from_str("response serialization failed"))
}

async fn serve_inner<A: Application>(
    application: &A,
    metadata: Vec<u8>,
    body: Vec<u8>,
    config: &crate::RuntimeConfig,
) -> Result<ResponseEnvelope, u16> {
    let mut parsed: RequestMetadata = serde_json::from_slice(&metadata).map_err(|_| 500u16)?;
    let request_config = parsed.config.take();
    let config = request_config.as_ref().unwrap_or(config);
    let rid = parsed
        .id
        .unwrap_or_else(|| NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed));
    crate::logging::scope(rid, serve_request(application, parsed, body, config, rid)).await
}

async fn serve_request<A: Application>(
    application: &A,
    parsed: RequestMetadata,
    body: Vec<u8>,
    config: &crate::RuntimeConfig,
    rid: u64,
) -> Result<ResponseEnvelope, u16> {
    let origin = parsed
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("origin"));
    if A::AUTH_ENABLED
        && origin.is_some_and(|(_, origin)| !A::ALLOWED_ORIGINS.contains(&origin.as_str()))
    {
        return Ok(error_envelope(403, "origin_denied"));
    }
    if A::AUTH_ENABLED && origin.is_some() && parsed.method == "OPTIONS" {
        return Ok(ResponseEnvelope {
            status: 204,
            body: serde_json::Value::Null,
        });
    }
    if body.len() > TOKEN_LIMIT {
        return Ok(error_envelope(413, "request_too_large"));
    }
    if parsed.method != "POST" || !parsed.query.is_empty() {
        return Ok(error_envelope(404, "not_found"));
    }
    let operation = match parsed.path.strip_prefix('/') {
        Some(operation) if !operation.is_empty() => operation.to_string(),
        _ => return Ok(error_envelope(404, "not_found")),
    };
    if operation.starts_with("auth.") || !application.accepts(&operation) {
        return Ok(error_envelope(404, "not_found"));
    }
    let content_type = parsed
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.split(';').next().unwrap_or("").trim().to_string());
    if content_type.as_deref() != Some("application/json") {
        return Ok(error_envelope(415, "unsupported_media_type"));
    }
    let has_database = parsed
        .database
        .unwrap_or_else(|| config.database_url.is_some());
    if A::REQUIRES_DATABASE && !has_database {
        return Ok(error_envelope(503, "service_unavailable"));
    }
    let input = match serde_json::from_slice::<json::Input>(&body) {
        Ok(json::Input(value)) if value.is_object() => value,
        Err(_) if !json::is_valid(&body) => return Ok(error_envelope(400, "invalid_json")),
        _ => return Ok(error_envelope(400, "invalid_input")),
    };
    let mut pending = vec![(&input, 1)];
    while let Some((value, depth)) = pending.pop() {
        if !value.is_object() && !value.is_array() {
            continue;
        }
        if depth > 64 {
            return Ok(error_envelope(400, "invalid_input"));
        }
        match value {
            serde_json::Value::Object(object) => {
                pending.extend(object.values().map(|value| (value, depth + 1)));
            }
            serde_json::Value::Array(array) => {
                pending.extend(array.iter().map(|value| (value, depth + 1)));
            }
            _ => unreachable!(),
        }
    }
    let session = match (A::AUTH_ENABLED, parsed.auth) {
        (false, None)
        | (
            true,
            Some(HostAuthentication {
                version: 1,
                session: None,
            }),
        ) => None,
        (
            true,
            Some(HostAuthentication {
                version: 1,
                session: Some(session),
            }),
        ) if !session.id.is_empty()
            && !session.user.id.is_empty()
            && !session.user.email.is_empty() =>
        {
            Some(Session {
                id: session.id,
                user: session.user,
            })
        }
        _ => return Ok(error_envelope(500, "operation_failed")),
    };
    let mut headers = parsed.headers;
    headers.retain(|(name, _)| !is_credential_header(name, A::AUTH_ENABLED));
    let runtime = RuntimeContext {
        rid,
        method: parsed.method,
        path: parsed.path,
        query: parsed.query,
        headers,
        session,
        database: has_database.then(|| DatabasePort::new(rid)),
        secrets: config.secrets.clone(),
        vault: Vault::from_config(config),
    };
    let context = A::Context::build(&runtime);
    match application.invoke(&context, &operation, input).await {
        Ok(output) => Ok(ResponseEnvelope {
            status: 200,
            body: output,
        }),
        Err(DispatchError::InvalidInput(_)) => Ok(error_envelope(400, "invalid_input")),
        Err(DispatchError::Operation(error)) => Ok(operation_error_envelope(
            error,
            application.input_fields(&operation),
        )),
        Err(DispatchError::Internal) => Ok(error_envelope(500, "operation_failed")),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{auth, host::testing};
    use serde_json::{Value, json};
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        rc::Rc,
    };

    struct Context {
        headers: Vec<(String, String)>,
        request: RequestView,
        session: Option<Session>,
    }

    impl ProjectContext for Context {
        fn build(runtime: &RuntimeContext) -> Self {
            Self {
                headers: runtime.headers.clone(),
                request: runtime.request_view(),
                session: runtime.session.clone(),
            }
        }
    }

    struct App<const AUTH: bool, const DATABASE: bool>;

    impl<const AUTH: bool, const DATABASE: bool> Application for App<AUTH, DATABASE> {
        type Context = Context;
        const AUTH_ENABLED: bool = AUTH;
        const REQUIRES_DATABASE: bool = DATABASE;
        const SESSION_IDLE_TIMEOUT_SECONDS: u64 = 3_600;

        fn accepts(&self, operation: &str) -> bool {
            operation == "probe.headers"
        }

        async fn invoke(
            &self,
            context: &Context,
            _operation: &str,
            _input: Value,
        ) -> Result<Value, DispatchError> {
            Ok(json!({
                "headers": context.headers,
                "request_headers": context.request.headers,
                "authenticated": context.session.is_some(),
                "session_id": context.session.as_ref().map(|session| &session.id),
                "user_id": context.session.as_ref().map(|session| &session.user.id),
            }))
        }
    }

    fn host_auth_request(auth: Option<Value>, credentials: bool) -> (ResponseEnvelope, usize) {
        let mut frame = json!({
            "id": 47,
            "method": "POST",
            "path": "/probe.headers",
            "headers": [["content-type", "application/json"], ["x-request-label", "visible"]],
        });
        if let Some(auth) = auth {
            frame["auth"] = auth;
        }
        if credentials {
            frame["headers"].as_array_mut().unwrap().extend([
                json!(["aUtHoRiZaTiOn", format!("Bearer {:043}", 1)]),
                json!(["cOoKiE", "test-only=unused"]),
                json!(["Proxy-Authorization", "test-only"]),
            ]);
        }
        let calls = Rc::new(Cell::new(0));
        let database_calls = calls.clone();
        let config = crate::RuntimeConfig {
            database_url: Some("configured".into()),
            ..Default::default()
        };
        let result = testing::run(
            move |_| {
                database_calls.set(database_calls.get() + 1);
                json!({"rows": []})
            },
            serve_inner(
                &App::<true, true>,
                serde_json::to_vec(&frame).unwrap(),
                b"{}".to_vec(),
                &config,
            ),
        )
        .unwrap_or_else(|status| error_envelope(status, "operation_failed"));
        (result, calls.get())
    }

    fn host_auth_session() -> Value {
        json!({"version": 1, "session": {
            "id": "session-id", "user": {"id": "user-id", "email": "user@example.test"},
        }})
    }

    #[test]
    fn host_auth_projects_session_without_native_lookup() {
        let (response, database_calls) = host_auth_request(Some(host_auth_session()), false);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["session_id"], "session-id");
        assert_eq!(response.body["user_id"], "user-id");
        assert_eq!(database_calls, 0);
    }

    #[test]
    fn host_auth_distinguishes_anonymous_from_invalid_frames() {
        let (response, database_calls) =
            host_auth_request(Some(json!({"version": 1, "session": null})), false);
        assert_eq!(response.status, 200);
        assert_eq!(response.body["authenticated"], false);
        assert_eq!(database_calls, 0);
        for frame in [
            None,
            Some(Value::Null),
            Some(json!({"version": 1})),
            Some(json!({"version": 2, "session": null})),
            Some(json!({"version": 1, "session": {"id": "incomplete"}})),
        ] {
            let (response, database_calls) = host_auth_request(frame, false);
            assert_eq!(response.status, 500);
            assert_eq!(response.body, json!({"error": "operation_failed"}));
            assert_eq!(database_calls, 0);
        }
    }

    #[test]
    fn host_auth_does_not_forward_or_revalidate_credential_headers() {
        let (response, database_calls) = host_auth_request(Some(host_auth_session()), true);
        assert_eq!(database_calls, 0);
        assert_eq!(response.status, 200);
        let expected = json!([
            ["content-type", "application/json"],
            ["x-request-label", "visible"]
        ]);
        assert_eq!(response.body["headers"], expected);
        assert_eq!(response.body["request_headers"], expected);
    }

    struct HookProbe {
        created: Cell<usize>,
    }

    impl auth::UserCreationHooks for &HookProbe {
        async fn creating(
            &self,
            port: crate::database::TransactionPort,
            user: &auth::AuthUser,
        ) -> Result<(), OperationError> {
            assert_eq!(user.id, "new-user");
            assert_eq!(user.created_at, "2026-11-20T00:00:00.000000Z");
            port.query("domain write", &[]).await?;
            assert!(port.commit().await.is_err());
            port.rollback().await;
            Err(OperationError::internal())
        }

        async fn committed(&self, _user: &auth::AuthUser) -> Result<(), OperationError> {
            self.created.set(self.created.get() + 1);
            Ok(())
        }
    }

    impl Application for HookProbe {
        type Context = Context;
        const AUTH_ENABLED: bool = true;
        const REQUIRES_DATABASE: bool = true;

        fn accepts(&self, _: &str) -> bool {
            false
        }

        fn auth_hooks(&self) -> impl auth::UserCreationHooks {
            self
        }

        async fn invoke(&self, _: &Context, _: &str, _: Value) -> Result<Value, DispatchError> {
            panic!("hook reached business dispatch")
        }
    }

    #[test]
    fn host_auth_creation_hook_only_queries_the_borrowed_lease() {
        let probe = HookProbe {
            created: Cell::new(0),
        };
        let mut frame = json!({"version": 1, "hook": "userCreating", "user": {
            "id": "new-user", "email": "user@example.test", "createdAt": "2026-11-20T00:00:00.000000Z"
        }});
        let frame_bytes = serde_json::to_vec(&frame).unwrap();
        let calls = Rc::new(RefCell::new(Vec::new()));
        let host_calls = calls.clone();
        let result = testing::run(
            move |call| {
                host_calls.borrow_mut().push(call);
                json!({"rows": []})
            },
            serve_auth_hook(&probe, &frame_bytes, 47, Some(9)),
        );
        assert!(
            matches!(result, Err(error) if error.code == "user_creation_failed" && error.status == 500)
        );
        assert_eq!(
            *calls.borrow(),
            vec![json!({"op":"exec", "rid":47, "lease":9, "sql":"domain write", "params":[]})]
        );
        assert_eq!(probe.created.get(), 0);

        frame["hook"] = json!("userCreated");
        let frame_bytes = serde_json::to_vec(&frame).unwrap();
        let no_db = |_| panic!("unexpected database call in post-commit hook");
        let wrong = testing::run(no_db, serve_auth_hook(&probe, &frame_bytes, 47, Some(9)));
        assert!(matches!(wrong, Err(error) if error.code == "operation_failed"));
        assert_eq!(probe.created.get(), 0);
        let result = testing::run(no_db, serve_auth_hook(&probe, &frame_bytes, 47, None));
        assert!(result.is_ok());
        assert_eq!(probe.created.get(), 1);
    }

    struct InputApp<const AUTH: bool>(Cell<usize>);

    impl<const AUTH: bool> Application for InputApp<AUTH> {
        type Context = Context;
        const AUTH_ENABLED: bool = AUTH;
        const EMAIL_PASSWORD_ENABLED: bool = AUTH;
        const REQUIRES_DATABASE: bool = false;

        fn accepts(&self, _operation: &str) -> bool {
            true
        }

        fn auth_hooks(&self) -> impl auth::UserCreationHooks {
            assert!(!AUTH, "invalid input reached authentication");
            auth::NoHooks
        }

        async fn invoke(
            &self,
            _context: &Context,
            _operation: &str,
            _input: Value,
        ) -> Result<Value, DispatchError> {
            self.0.set(self.0.get() + 1);
            Ok(json!({"ok": true}))
        }
    }

    fn input_request<const AUTH: bool>(
        application: &InputApp<AUTH>,
        operation: &str,
        body: impl Into<Vec<u8>>,
    ) -> ResponseEnvelope {
        testing::run(
            |_| panic!("invalid input reached the host"),
            serve_inner(
                application,
                serde_json::to_vec(&json!({
                    "method": "POST", "path": format!("/{operation}"),
                    "headers": [["Content-Type", "application/json"]],
                }))
                .unwrap(),
                body.into(),
                &crate::RuntimeConfig::default(),
            ),
        )
        .unwrap()
    }

    fn nested_input(depth: usize, leaf: &str, in_list: bool) -> String {
        let arrays = depth - if in_list { 3 } else { 1 };
        let value = format!("{}{}{}", "[".repeat(arrays), leaf, "]".repeat(arrays));
        if in_list {
            format!(
                r#"{{"required_name":"required","nullable_name":null,"entries":[],"large_rows":[{{"payload":"present","ignored":{value}}}]}}"#
            )
        } else {
            format!(r#"{{"name":"structure","note":"ok","ignored":{value}}}"#)
        }
    }

    #[test]
    fn input_structure_limits() {
        for (name, operation, body, status, calls) in [
            (
                "duplicate-key",
                "catalog.create",
                r#"{"name":"first","name":"second"}"#.to_string(),
                400,
                0,
            ),
            (
                "nested-duplicate-key",
                "catalog.create",
                nested_input(63, r#"{"na\u006de":0,"name":1}"#, false),
                400,
                0,
            ),
            (
                "escaped-duplicate-key",
                "catalog.create",
                r#"{"a":1,"\u0061":2}"#.to_string(),
                400,
                0,
            ),
            (
                "overwritten-overflow",
                "catalog.create",
                r#"{"ignored":1e999,"ignored":0}"#.to_string(),
                400,
                0,
            ),
            (
                "overwritten-deep-value",
                "catalog.create",
                format!(
                    r#"{{"ignored":{}null{},"ignored":0}}"#,
                    "[".repeat(20000),
                    "]".repeat(20000)
                ),
                400,
                0,
            ),
            (
                "overflowing-long-integer",
                "catalog.create",
                format!(r#"{{"ignored":{}}}"#, "9".repeat(309)),
                400,
                0,
            ),
            (
                "overflowing-5000-digit-integer",
                "catalog.create",
                format!(r#"{{"ignored":{}}}"#, "1".repeat(5000)),
                400,
                0,
            ),
            (
                "finite-300-digit-integer",
                "catalog.create",
                format!(r#"{{"ignored":{}}}"#, "1".repeat(300)),
                200,
                1,
            ),
            (
                "finite-long-integer",
                "catalog.create",
                format!(r#"{{"ignored":{}}}"#, "9".repeat(308)),
                200,
                1,
            ),
            (
                "finite-long-decimal",
                "catalog.create",
                format!(r#"{{"ignored":0.{}}}"#, "9".repeat(400)),
                200,
                1,
            ),
            (
                "unpaired-surrogate",
                "catalog.create",
                r#"{"ignored":"\uD800"}"#.to_string(),
                400,
                0,
            ),
            (
                "unpaired-surrogate-key",
                "catalog.create",
                r#"{"ignored":{"\uDC00":0}}"#.to_string(),
                400,
                0,
            ),
            (
                "distinct-objects-and-values",
                "catalog.create",
                r#"{"a":[{"name":"a\"}:[{\\x"},{"name":"b"}],"flags":[true,false],"b":"\uD834\uDD1E","c":-1,"d":18446744073709551615,"e":null,"f":1.25,"g":{}}"#.to_string(),
                200,
                1,
            ),
            (
                "unknown-depth-65",
                "catalog.create",
                nested_input(65, "null", false),
                400,
                0,
            ),
            (
                "unknown-depth-64",
                "catalog.create",
                nested_input(64, "null", false),
                200,
                1,
            ),
            (
                "declared-list-depth-64",
                "catalog.inspect_optional",
                nested_input(64, "null", true),
                200,
                1,
            ),
            (
                "unknown-positive-overflow",
                "catalog.create",
                nested_input(1, "1e999", false),
                400,
                0,
            ),
            (
                "nested-negative-overflow",
                "catalog.inspect_optional",
                nested_input(3, "-1e999", true),
                400,
                0,
            ),
            (
                "unknown-finite-double",
                "catalog.create",
                nested_input(1, "1e308", false),
                200,
                1,
            ),
            (
                "reject-before-serialization",
                "catalog.inspect_optional",
                nested_input(20000, "null", false),
                400,
                0,
            ),
        ] {
            let application = InputApp::<false>(Cell::new(0));
            let response = input_request(&application, operation, body);
            eprintln!(
                "{name}: status={}, body={}, handler_calls={}",
                response.status,
                response.body,
                application.0.get()
            );
            assert_eq!(
                (response.status, application.0.get()),
                (status, calls),
                "{name}"
            );
            assert_eq!(
                response.body,
                if status == 400 {
                    json!({"error": "invalid_input"})
                } else {
                    json!({"ok": true})
                },
                "{name}"
            );
        }
    }

    #[test]
    fn input_json_errors_precede_structure_limits() {
        for (name, body, code) in [
            (
                "syntax-after-duplicate-key",
                br#"{"a":1,"a":2,}"#.to_vec(),
                "invalid_json",
            ),
            ("unclosed-object", b"{".to_vec(), "invalid_json"),
            (
                "unclosed-arrays",
                "[".repeat(65).into_bytes(),
                "invalid_json",
            ),
            (
                "invalid-token-after-arrays",
                format!("{}?", "[".repeat(65)).into_bytes(),
                "invalid_json",
            ),
            (
                "malformed-unclosed-depth-65",
                format!(r#"{{"name":"structure","note":{}}}"#, "[".repeat(65)).into_bytes(),
                "invalid_json",
            ),
            (
                "malformed-token-after-depth-65",
                format!(
                    r#"{{"name":"structure","note":{}null{}!}}"#,
                    "[".repeat(65),
                    "]".repeat(65)
                )
                .into_bytes(),
                "invalid_json",
            ),
            (
                "syntax-after-recursion-limit",
                nested_input(129, "?", false).into_bytes(),
                "invalid_json",
            ),
            (
                "valid-after-recursion-limit",
                nested_input(129, "null", false).into_bytes(),
                "invalid_input",
            ),
            (
                "number-overflow",
                b"{\"ignored\":1e999}".to_vec(),
                "invalid_input",
            ),
            (
                "syntax-after-overflow",
                b"{\"ignored\":1e999,}".to_vec(),
                "invalid_json",
            ),
            (
                "invalid-utf8",
                b"{\"name\":\"\xff\"}".to_vec(),
                "invalid_json",
            ),
            ("non-object", b"[]".to_vec(), "invalid_input"),
        ] {
            let application = InputApp::<false>(Cell::new(0));
            let response = input_request(&application, "catalog.create", body);
            eprintln!(
                "{name}: status={}, body={}, handler_calls={}",
                response.status,
                response.body,
                application.0.get()
            );
            assert_eq!(response.status, 400, "{name}");
            assert_eq!(response.body, json!({"error": code}), "{name}");
            assert_eq!(application.0.get(), 0, "{name}");
        }
    }

    #[test]
    fn host_auth_builtin_operations_do_not_dispatch_in_rust() {
        let application = InputApp::<true>(Cell::new(0));
        let response = input_request(&application, "auth.signup", "{}");
        assert_eq!(response.status, 404);
        assert_eq!(response.body, json!({"error": "not_found"}));
        assert_eq!(application.0.get(), 0);
    }

    fn metadata(operation: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "method": "POST", "path": format!("/{operation}"),
            "headers": [
                ["pRoXy-AuThOrIzAtIoN", "proxy-credential"],
                ["Proxy-Authorization", "proxy-credential-duplicate"],
                ["Content-Type", "application/json"],
                ["aUtHoRiZaTiOn", format!("Bearer {:043}", 1)],
                ["Authorization", format!("Bearer {:043}", 2)],
                ["cOoKiE", "custom=session"],
                ["Cookie", "custom=session-duplicate"],
                ["X-Request-Label", "visible"],
                ["Origin", "https://app.example.test"],
            ],
        }))
        .unwrap()
    }

    fn request<A: Application>(
        application: A,
        operation: &str,
        database: bool,
        script: Vec<(&'static str, Value)>,
    ) -> ResponseEnvelope {
        validate_application(&application).unwrap();
        let responses = Rc::new(RefCell::new(VecDeque::from(script)));
        let host = responses.clone();
        let config = crate::RuntimeConfig {
            database_url: database.then(|| "configured".into()),
            ..Default::default()
        };
        let mut metadata: Value = serde_json::from_slice(&metadata(operation)).unwrap();
        if A::AUTH_ENABLED {
            metadata["headers"].as_array_mut().unwrap().pop();
        }
        let response = testing::run(
            move |request| {
                let (operation, response) = host
                    .borrow_mut()
                    .pop_front()
                    .expect("unexpected authentication database call");
                assert!(request["op"] == operation, "unexpected host operation");
                response
            },
            serve_inner(
                &application,
                serde_json::to_vec(&metadata).unwrap(),
                b"{}".to_vec(),
                &config,
            ),
        )
        .unwrap();
        assert!(
            responses.borrow().is_empty(),
            "missing authentication lookup"
        );
        response
    }

    fn timestamp(delta: i64) -> String {
        chrono::DateTime::from_timestamp_millis(testing::NOW + delta)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }

    fn session_script(stored_delta: i64, legacy: bool) -> Vec<(&'static str, Value)> {
        let session_id = format!("00000000-0000-4000-8000-{:012}", 1);
        let user_id = format!("00000000-0000-4000-8000-{:012}", 2);
        let session = json!({
            "id": session_id, "user_id": user_id, "user_session_version": 1,
            "created_at": timestamp(-172_800_000),
            "first_login_at": if legacy { Value::Null } else { json!(timestamp(-172_800_000)) },
            "last_renewed_at": if legacy { Value::Null } else { json!(timestamp(-600_000)) },
            "expires_at": timestamp(900_000), "revoked_at": null,
            "token_hash": "", "transport": "native",
        });
        vec![
            ("query", json!({"rows": [session.clone()]})),
            ("begin", json!({"lease": 7})),
            ("exec", json!({"rows": [session]})),
            (
                "exec",
                json!({"rows": [{
                    "id": format!("00000000-0000-4000-8000-{:012}", 3),
                    "session_id": session_id, "token_hash": "",
                    "created_at": timestamp(-600_000),
                    "expires_at": timestamp(stored_delta), "consumed_at": null,
                }]}),
            ),
            (
                "exec",
                json!({"rows": [{
                    "id": user_id, "email": "user@example.test", "session_version": 1,
                    "created_at": timestamp(-172_800_000),
                    "disabled_at": null, "email_verified_at": null, "password_hash": null,
                }]}),
            ),
            ("commit", json!({})),
        ]
    }

    #[test]
    fn auth_disabled_preserves_application_credentials_and_removes_proxy_credentials() {
        for response in [
            request(App::<false, true>, "probe.headers", true, vec![]),
            request(App::<false, false>, "probe.headers", false, vec![]),
        ] {
            assert_eq!(response.status, 200);
            let mut metadata: Value = serde_json::from_slice(&metadata("probe.headers")).unwrap();
            metadata["headers"]
                .as_array_mut()
                .unwrap()
                .retain(|header| {
                    !header[0]
                        .as_str()
                        .unwrap()
                        .eq_ignore_ascii_case("proxy-authorization")
                });
            for key in ["headers", "request_headers"] {
                assert_eq!(
                    response.body[key]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|header| {
                            header[0]
                                .as_str()
                                .unwrap()
                                .eq_ignore_ascii_case("proxy-authorization")
                        })
                        .count(),
                    0,
                    "proxy credential header reached customer code"
                );
                assert!(
                    response.body[key] == metadata["headers"],
                    "credential headers changed"
                );
            }
            assert_eq!(response.body["authenticated"], false);
        }
        for response in [
            request(App::<false, true>, "auth.session", true, vec![]),
            request(App::<false, false>, "auth.session", false, vec![]),
        ] {
            assert_eq!(response.status, 404);
            assert_eq!(response.body["error"], "not_found");
        }
        let missing_database = request(App::<false, true>, "probe.headers", false, vec![]);
        assert_eq!(missing_database.status, 503);
    }

    #[test]
    fn native_session_reports_earlier_stored_or_current_policy_expiry() {
        let hooks = auth::NoHooks;
        let native = auth::Auth::new(DatabasePort::new(47), &[], &hooks)
            .and_then(|auth| auth.with_session_policy(3_600, 0))
            .unwrap_or_else(|_| panic!("native auth fixture failed"));
        for legacy in [false, true] {
            for (stored_delta, expected_delta) in [(60_000, 60_000), (86_400_000, 3_000_000)] {
                let mut script = VecDeque::from(session_script(stored_delta, legacy));
                let session = testing::run(
                    move |request| {
                        let (op, reply) = script.pop_front().expect("unexpected auth call");
                        assert_eq!(request["op"], op);
                        reply
                    },
                    native.session(&format!("{:043}", 1)),
                );
                assert!(
                    matches!(session, Ok(session) if session.expires_at == timestamp(expected_delta))
                );
            }
        }
    }

    struct CustomHooks;
    impl auth::UserCreationHooks for CustomHooks {}

    struct HooksApp;
    impl Application for HooksApp {
        type Context = Context;
        const AUTH_ENABLED: bool = false;
        const REQUIRES_DATABASE: bool = false;
        fn accepts(&self, _operation: &str) -> bool {
            unreachable!()
        }
        fn auth_hooks(&self) -> impl auth::UserCreationHooks {
            CustomHooks
        }
        async fn invoke(
            &self,
            _context: &Context,
            _operation: &str,
            _input: Value,
        ) -> Result<Value, DispatchError> {
            unreachable!()
        }
    }

    struct ProviderApp(Vec<Box<dyn auth::IdentityProvider>>);
    impl Application for ProviderApp {
        type Context = Context;
        const AUTH_ENABLED: bool = false;
        const REQUIRES_DATABASE: bool = false;
        fn accepts(&self, _operation: &str) -> bool {
            unreachable!()
        }
        fn identity_providers(&self) -> &[Box<dyn auth::IdentityProvider>] {
            &self.0
        }
        async fn invoke(
            &self,
            _context: &Context,
            _operation: &str,
            _input: Value,
        ) -> Result<Value, DispatchError> {
            unreachable!()
        }
    }

    struct Provider;
    impl auth::IdentityProvider for Provider {
        fn id(&self) -> &str {
            unreachable!()
        }
        fn verify<'a>(
            &'a self,
            _credential: &'a Value,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<auth::VerifiedIdentity, OperationError>>
                    + 'a,
            >,
        > {
            unreachable!()
        }
    }

    fn vault(scope: &str, project: &str, raw: Option<&str>) -> Vault {
        Vault {
            scope: scope.to_string(),
            project: project.to_string(),
            raw: raw.map(str::to_string),
        }
    }

    #[test]
    fn empty_declared_secret_is_unavailable() {
        let runtime = RuntimeContext {
            rid: 1,
            method: String::new(),
            path: String::new(),
            query: String::new(),
            headers: Vec::new(),
            session: None,
            database: None,
            secrets: [("TOKEN".into(), String::new())].into(),
            vault: Vault::from_config(&crate::RuntimeConfig::default()),
        };
        for name in ["TOKEN", "MISSING"] {
            match runtime.secret(name) {
                Err(error) => {
                    assert_eq!(error.code, "service_unavailable");
                    assert_eq!(error.status, 503);
                }
                Ok(_) => panic!("missing or empty secret was accepted"),
            }
        }
    }

    #[test]
    fn vault_rejects_foreign_scope_project_and_missing_secrets() {
        let raw = r#"{"projectId":"11111111-1111-4111-8111-111111111111","vault":"fixture","values":{"VALUE":"vault"}}"#;
        let bound = vault("fixture", "11111111-1111-4111-8111-111111111111", Some(raw));
        assert!(matches!(bound.get("VALUE"), Ok(value) if value == "vault"));
        for rejected in [
            vault("", "11111111-1111-4111-8111-111111111111", Some(raw)),
            vault("fixture", "", Some(raw)),
            vault("fixture", "11111111-1111-4111-8111-111111111111", None),
            vault("fixture", "11111111-1111-4111-8111-111111111111", Some("")),
            vault(
                "fixture",
                "11111111-1111-4111-8111-111111111111",
                Some("not json"),
            ),
            vault("other", "11111111-1111-4111-8111-111111111111", Some(raw)),
            vault("fixture", "22222222-2222-4222-8222-222222222222", Some(raw)),
            vault(
                "fixture",
                "11111111-1111-4111-8111-111111111111",
                Some(
                    r#"{"projectId":"11111111-1111-4111-8111-111111111111","vault":"fixture","values":{"VALUE":1}}"#,
                ),
            ),
        ] {
            match rejected.get("VALUE") {
                Err(error) => {
                    assert_eq!(error.code, "service_unavailable");
                    assert_eq!(error.status, 503);
                }
                Ok(value) => panic!("vault binding was accepted: {value}"),
            }
        }
        match bound.get("MISSING") {
            Err(error) => {
                assert_eq!(error.code, "operation_failed");
                assert_eq!(error.status, 500);
            }
            Ok(value) => panic!("missing vault secret was accepted: {value}"),
        }
    }

    #[test]
    fn realtime_publish_maps_host_outcomes_to_public_errors() {
        crate::host::testing::run_storage(
            |request| {
                assert_eq!(
                    request,
                    serde_json::json!({
                        "rid": 7,
                        "op": "publish",
                        "input": { "channel": "orders", "payload": { "id": "A", "items": [1, 2] } },
                    })
                );
                serde_json::json!({})
            },
            async {
                let payload = serde_json::json!({ "id": "A", "items": [1, 2] });
                if let Err(error) = Realtime::new(7).publish("orders", &payload).await {
                    panic!("realtime publish failed: {} {}", error.code, error.status);
                }
            },
        );
        for (script, code, status) in [
            (
                serde_json::json!({ "error": "binding_unavailable" }),
                "service_unavailable",
                503,
            ),
            (
                serde_json::json!({ "error": "unauthorized_project", "status": 403 }),
                "unauthorized_project",
                403,
            ),
            (
                serde_json::json!({ "error": "realtime_publish_outcome_unknown", "status": 503 }),
                "realtime_publish_outcome_unknown",
                503,
            ),
            (
                serde_json::json!({ "error": "invalid_host_call" }),
                "operation_failed",
                500,
            ),
            (
                serde_json::json!({ "error": "Bad_Code", "status": 403 }),
                "operation_failed",
                500,
            ),
            (
                serde_json::json!({ "error": "unauthorized_project", "status": 200 }),
                "operation_failed",
                500,
            ),
            (serde_json::json!({ "ok": true }), "operation_failed", 500),
        ] {
            crate::host::testing::run_storage(move |_| script.clone(), async move {
                match Realtime::new(1).publish("orders", &1).await {
                    Err(error) => {
                        assert_eq!(error.code, code);
                        assert_eq!(error.status, status);
                    }
                    Ok(()) => panic!("realtime host reply was accepted as confirmed"),
                }
            });
        }
    }

    #[test]
    fn storage_maps_host_outcomes_to_public_errors() {
        crate::host::testing::run_storage(
            |request| {
                assert_eq!(request["name"], "assets");
                match request["op"].as_str() {
                    Some("get") if request["key"] == "missing" => {
                        serde_json::json!({ "value": null })
                    }
                    Some("get") => serde_json::json!({ "value": [0, 255, 1] }),
                    Some("put") => serde_json::json!({}),
                    _ => unreachable!(),
                }
            },
            async {
                let storage = Storage::new(1, "assets");
                match storage.get("object").await {
                    Ok(value) => assert_eq!(value, Some(vec![0, 255, 1])),
                    Err(error) => panic!("storage read failed: {} {}", error.code, error.status),
                }
                match storage.get("missing").await {
                    Ok(value) => assert_eq!(value, None),
                    Err(error) => panic!("storage read failed: {} {}", error.code, error.status),
                }
                match storage
                    .put("object", vec![0, 255, 1], "application/octet-stream")
                    .await
                {
                    Ok(()) => {}
                    Err(error) => panic!("storage write failed: {} {}", error.code, error.status),
                }
            },
        );
        for (script, code, status) in [
            (
                serde_json::json!({ "error": "service_unavailable" }),
                "service_unavailable",
                503,
            ),
            (
                serde_json::json!({ "error": "operation_failed" }),
                "operation_failed",
                500,
            ),
        ] {
            crate::host::testing::run_storage(move |_| script.clone(), async move {
                match Storage::new(1, "assets").get("object").await {
                    Err(error) => {
                        assert_eq!(error.code, code);
                        assert_eq!(error.status, status);
                    }
                    Ok(value) => panic!("storage host error was accepted: {value:?}"),
                }
            });
        }
        crate::host::testing::run_storage(
            |_| unreachable!("oversized objects must not reach the storage host"),
            async {
                let error = Storage::new(1, "assets")
                    .put("object", vec![0; (4 << 20) + 1], "application/octet-stream")
                    .await
                    .unwrap_err();
                assert_eq!(error.code, "operation_failed");
            },
        );
    }

    #[test]
    fn auth_disabled_rejects_registered_hooks_and_providers_before_dispatch() {
        use auth::UserCreationHooks;
        assert!(CustomHooks.is_registered());
        assert!(!auth::NoHooks.is_registered());
        assert_eq!(
            validate_application(&HooksApp),
            Err("declare auth in auth.yml")
        );
        assert_eq!(
            validate_application(&ProviderApp(vec![Box::new(Provider)])),
            Err("declare auth in auth.yml")
        );
        assert_eq!(validate_application(&App::<false, false>), Ok(()));
    }
}
