//! Wire protocol and application serving. Semantics mirror the other server
//! languages: POST to one operation path, JSON bodies, bounded requests,
//! opaque bearer tokens, typed error envelopes, and no retry on business
//! failures.

use crate::database::DatabasePort;
use crate::wasm_bindgen;
use std::sync::atomic::{AtomicU64, Ordering};

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
}

/// Project secrets resolved from the private binding frame. Missing values
/// surface at access time with the shared service_unavailable status.
#[derive(Clone)]
pub struct Secrets {
    values: std::collections::BTreeMap<String, String>,
}

impl Secrets {
    pub fn from_config() -> Secrets {
        Secrets {
            values: crate::config().secrets.clone(),
        }
    }

    pub fn get(&self, name: &str) -> Result<String, OperationError> {
        self.values
            .get(name)
            .cloned()
            .ok_or_else(|| OperationError::new("service_unavailable", 503))
    }
}

impl RuntimeContext {
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

/// One authenticated application session, resolved from the private bearer
/// token through the authentication core.
#[derive(Clone)]
pub struct Session {
    pub id: String,
    pub user: SessionUser,
    pub expires_at: String,
}

#[derive(Clone)]
pub struct SessionUser {
    pub id: String,
    pub email: String,
}

/// Public operation error with its HTTP status and stable error code.
#[derive(Clone)]
pub struct OperationError {
    pub code: String,
    pub status: u16,
    database_code: Option<String>,
}

impl OperationError {
    pub fn new(code: &str, status: u16) -> OperationError {
        let allowed = !code.is_empty()
            && code.len() <= 64
            && code
                .chars()
                .all(|character| character.is_ascii_lowercase() || character == '_');
        if !allowed {
            return Self::internal();
        }
        OperationError {
            code: code.to_string(),
            status,
            database_code: None,
        }
    }

    /// Generic internal failure. Internal details never reach the wire.
    pub fn internal() -> OperationError {
        OperationError {
            code: "operation_failed".to_string(),
            status: 500,
            database_code: None,
        }
    }

    pub fn unauthenticated() -> OperationError {
        Self::new("unauthenticated", 401)
    }

    pub fn invalid_token() -> OperationError {
        Self::new("invalid_token", 401)
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
    id: Option<u64>,
    method: String,
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
}

struct ResponseEnvelope {
    status: u16,
    body: serde_json::Value,
}

fn error_envelope(status: u16, code: &str) -> ResponseEnvelope {
    ResponseEnvelope {
        status,
        body: serde_json::json!({ "error": code }),
    }
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
    let parsed: RequestMetadata = serde_json::from_slice(&metadata).map_err(|_| 500u16)?;
    let rid = parsed
        .id
        .unwrap_or_else(|| NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed));
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
    let builtin = A::AUTH_ENABLED
        && (matches!(
            operation.as_str(),
            "auth.refresh" | "auth.session" | "auth.logout" | "auth.identity"
        ) || A::EMAIL_PASSWORD_ENABLED
            && matches!(operation.as_str(), "auth.signup" | "auth.signin"));
    if !builtin && !application.accepts(&operation) {
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
    if A::REQUIRES_DATABASE && config.database_url.is_none() {
        return Ok(error_envelope(503, "service_unavailable"));
    }
    let input: serde_json::Value = match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(value) if value.is_object() => value,
        _ => return Ok(error_envelope(400, "invalid_input")),
    };
    let authorization = parsed
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("authorization"));
    let bearer = || -> Result<&str, OperationError> {
        let value = authorization
            .map(|(_, value)| value.as_str())
            .ok_or_else(OperationError::invalid_token)?;
        let (scheme, token) = value
            .split_once(' ')
            .ok_or_else(OperationError::invalid_token)?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.len() != 43
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(OperationError::invalid_token());
        }
        Ok(token)
    };
    let text = |key: &str| {
        input
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| OperationError::new("invalid_input", 400))
    };
    let mut session = None;
    if A::AUTH_ENABLED {
        let hooks = application.auth_hooks();
        let auth = match crate::auth::Auth::new(
            DatabasePort::new(rid),
            application.identity_providers(),
            &hooks,
        )
        .and_then(|auth| {
            auth.with_session_policy(
                A::SESSION_IDLE_TIMEOUT_SECONDS,
                A::SESSION_ABSOLUTE_LIFETIME_SECONDS,
            )
        }) {
            Ok(auth) => auth,
            Err(error) => return Ok(error_envelope(error.status, &error.code)),
        };
        if builtin {
            let output: Result<serde_json::Value, OperationError> = async {
                match operation.as_str() {
                    "auth.signup" => serde_json::to_value(auth.signup(text("email")?, text("password")?).await?).map_err(|_| OperationError::internal()),
                    "auth.signin" => serde_json::to_value(auth.signin(text("email")?, text("password")?).await?).map_err(|_| OperationError::internal()),
                    "auth.identity" => serde_json::to_value(auth.signin_identity(text("provider")?, input.get("credential").unwrap_or(&serde_json::Value::Null)).await?).map_err(|_| OperationError::internal()),
                    "auth.refresh" => serde_json::to_value(auth.refresh(text("refresh_token")?).await?).map_err(|_| OperationError::internal()),
                    "auth.session" => {
                        let session = auth.session(bearer()?).await?;
                        Ok(serde_json::json!({"id":session.user.id,"email":session.user.email,"session_id":session.id,"expires_at":session.expires_at}))
                    }
                    "auth.logout" => { auth.logout(bearer()?).await?; Ok(serde_json::json!({"status":"ok"})) }
                    _ => Err(OperationError::new("not_found", 404)),
                }
            }.await;
            return Ok(match output {
                Ok(body) => ResponseEnvelope { status: 200, body },
                Err(error) => error_envelope(error.status, &error.code),
            });
        }
        if authorization.is_some() {
            match async { auth.session(bearer()?).await }.await {
                Ok(value) => session = Some(value),
                Err(error) => return Ok(error_envelope(error.status, &error.code)),
            }
        }
    }
    let mut headers = parsed.headers;
    if A::AUTH_ENABLED {
        headers.retain(|(name, _)| {
            !name.eq_ignore_ascii_case("authorization") && !name.eq_ignore_ascii_case("cookie")
        });
    }
    let runtime = RuntimeContext {
        rid,
        method: parsed.method,
        path: parsed.path,
        query: parsed.query,
        headers,
        session,
        database: config.database_url.as_ref().map(|_| DatabasePort::new(rid)),
    };
    let context = A::Context::build(&runtime);
    match application.invoke(&context, &operation, input).await {
        Ok(output) => Ok(ResponseEnvelope {
            status: 200,
            body: output,
        }),
        Err(DispatchError::InvalidInput(_)) => Ok(error_envelope(400, "invalid_input")),
        Err(DispatchError::Operation(error)) => Ok(error_envelope(error.status, &error.code)),
        Err(DispatchError::Internal) => Ok(error_envelope(500, "operation_failed")),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::{auth, host::testing};
    use serde_json::{Value, json};
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

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
            }))
        }
    }

    fn metadata(operation: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "method": "POST", "path": format!("/{operation}"),
            "headers": [
                ["Content-Type", "application/json"],
                ["aUtHoRiZaTiOn", format!("Bearer {:043}", 1)],
                ["cOoKiE", "custom=session"],
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
                    "disabled_at": null, "password_hash": null,
                }]}),
            ),
            ("commit", json!({})),
        ]
    }

    #[test]
    fn auth_disabled_preserves_credentials_with_and_without_database() {
        for response in [
            request(App::<false, true>, "probe.headers", true, vec![]),
            request(App::<false, false>, "probe.headers", false, vec![]),
        ] {
            assert_eq!(response.status, 200);
            let metadata: Value = serde_json::from_slice(&metadata("probe.headers")).unwrap();
            for key in ["headers", "request_headers"] {
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
    fn auth_enabled_resolves_session_and_removes_credentials() {
        let response = request(
            App::<true, true>,
            "probe.headers",
            true,
            session_script(60_000, false),
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body["authenticated"], true);
        for key in ["headers", "request_headers"] {
            let headers = response.body[key].as_array().unwrap();
            assert!(
                headers.iter().all(|header| {
                    let name = header[0].as_str().unwrap();
                    !name.eq_ignore_ascii_case("authorization")
                        && !name.eq_ignore_ascii_case("cookie")
                }),
                "credential header reached customer code"
            );
            assert!(headers.iter().any(|header| header[0] == "X-Request-Label"));
        }
        let rejected = request(
            App::<true, true>,
            "probe.headers",
            true,
            vec![("query", json!({"rows": []}))],
        );
        assert_eq!(rejected.status, 401);
        assert_eq!(rejected.body["error"], "invalid_token");
    }

    #[test]
    fn auth_session_reports_earlier_stored_or_current_policy_expiry() {
        for legacy in [false, true] {
            for (stored_delta, expected_delta) in [(60_000, 60_000), (86_400_000, 3_000_000)] {
                let response = request(
                    App::<true, true>,
                    "auth.session",
                    true,
                    session_script(stored_delta, legacy),
                );
                assert_eq!(response.status, 200);
                assert_eq!(response.body["expires_at"], timestamp(expected_delta));
                let keys: Vec<_> = response
                    .body
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert_eq!(keys, ["email", "expires_at", "id", "session_id"]);
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
