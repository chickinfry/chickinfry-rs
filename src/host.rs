//! Host ABI. The engine glue provides the single imported entry point that
//! executes database operations through the shared PostgreSQL port of the
//! runtime host. Requests and responses are UTF-8 JSON frames routed by the
//! per-request identifier assigned by the glue.

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
unsafe extern "C" {
    #[wasm_bindgen(js_namespace = __chik)]
    pub safe fn db(request: Vec<u8>) -> js_sys::Promise;
    #[wasm_bindgen(catch, js_namespace = __chik, js_name = log)]
    safe fn host_log(request: Vec<u8>) -> Result<js_sys::Promise, wasm_bindgen::JsValue>;
    #[wasm_bindgen(catch, js_namespace = __chik, js_name = storage)]
    safe fn host_storage(
        rid: u64,
        operation: String,
        name: String,
        key: String,
        bytes: Option<wasm_bindgen::JsValue>,
        content_type: Option<String>,
    ) -> Result<js_sys::Promise, wasm_bindgen::JsValue>;
}

#[derive(serde::Serialize)]
pub(crate) struct HostRequest<'a> {
    rid: u64,
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sql: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a [serde_json::Value]>,
}

impl<'a> HostRequest<'a> {
    pub(crate) fn query(rid: u64, sql: &'a str, params: &'a [serde_json::Value]) -> Self {
        Self {
            rid,
            op: "query",
            lease: None,
            sql: Some(sql),
            params: Some(params),
        }
    }
    pub(crate) fn begin(rid: u64) -> Self {
        Self {
            rid,
            op: "begin",
            lease: None,
            sql: None,
            params: None,
        }
    }
    pub(crate) fn exec(
        rid: u64,
        lease: u64,
        sql: &'a str,
        params: &'a [serde_json::Value],
    ) -> Self {
        Self {
            rid,
            op: "exec",
            lease: Some(lease),
            sql: Some(sql),
            params: Some(params),
        }
    }
    pub(crate) fn finish(rid: u64, op: &'static str, lease: u64) -> Self {
        Self {
            rid,
            op,
            lease: Some(lease),
            sql: None,
            params: None,
        }
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct HostResponse {
    #[serde(default)]
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub lease: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
pub(crate) async fn call(request: HostRequest<'_>) -> Result<HostResponse, String> {
    let payload = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let value = wasm_bindgen_futures::JsFuture::from(db(payload))
        .await
        .map_err(format_host_rejection)?;
    let bytes = js_sys::Uint8Array::from(value).to_vec();
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

/// One storage host reply: object bytes for a read, a write confirmation, or
/// a stable host error code.
pub(crate) enum StorageOutcome {
    Value(Option<Vec<u8>>),
    Written,
    Error(String),
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
pub(crate) async fn storage(
    rid: u64,
    operation: &str,
    name: &str,
    key: &str,
    bytes: Option<&[u8]>,
    content_type: Option<&str>,
) -> Result<StorageOutcome, String> {
    let payload = bytes.map(|bytes| wasm_bindgen::JsValue::from(js_sys::Uint8Array::from(bytes)));
    let promise = host_storage(
        rid,
        operation.to_string(),
        name.to_string(),
        key.to_string(),
        payload,
        content_type.map(str::to_string),
    )
    .map_err(format_host_rejection)?;
    let response = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(format_host_rejection)?;
    read_storage_outcome(&response, operation)
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
fn read_storage_outcome(
    response: &wasm_bindgen::JsValue,
    operation: &str,
) -> Result<StorageOutcome, String> {
    use wasm_bindgen::JsCast;
    let invalid = || "the storage host returned an invalid response".to_string();
    if !response.is_object() {
        return Err(invalid());
    }
    let error = js_sys::Reflect::get(response, &"error".into()).map_err(|_| invalid())?;
    if !error.is_undefined() {
        return match error.as_string() {
            Some(code) if !code.is_empty() => Ok(StorageOutcome::Error(code)),
            _ => Err(invalid()),
        };
    }
    if operation == "put" {
        return Ok(StorageOutcome::Written);
    }
    let value = js_sys::Reflect::get(response, &"value".into()).map_err(|_| invalid())?;
    if value.is_undefined() {
        return Err(invalid());
    }
    if value.is_null() {
        return Ok(StorageOutcome::Value(None));
    }
    match value.dyn_into::<js_sys::Uint8Array>() {
        Ok(bytes) => Ok(StorageOutcome::Value(Some(bytes.to_vec()))),
        Err(_) => Err(invalid()),
    }
}

/// Cryptographically strong random bytes from the host. Used for opaque
/// session and refresh tokens; only their digests are ever persisted.
pub fn random_bytes(length: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
fn format_host_rejection(error: crate::wasm_bindgen::JsValue) -> String {
    let text = error.as_string();
    match text {
        Some(message) => message,
        None => "the database host rejected the operation".to_string(),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) async fn call(request: HostRequest<'_>) -> Result<HostResponse, String> {
    let payload = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let response = testing::respond(serde_json::from_slice(&payload).unwrap());
    serde_json::from_value(response).map_err(|error| error.to_string())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) async fn storage(
    rid: u64,
    operation: &str,
    name: &str,
    key: &str,
    bytes: Option<&[u8]>,
    content_type: Option<&str>,
) -> Result<StorageOutcome, String> {
    let frame = serde_json::json!({
        "rid": rid,
        "op": operation,
        "name": name,
        "key": key,
        "bytes": bytes,
        "contentType": content_type,
    });
    let response = testing::storage_respond(frame);
    if let Some(code) = response.get("error").and_then(serde_json::Value::as_str) {
        return Ok(StorageOutcome::Error(code.to_string()));
    }
    match operation {
        "put" => Ok(StorageOutcome::Written),
        _ => match response.get("value") {
            None => Err("the storage host returned an invalid response".to_string()),
            Some(serde_json::Value::Null) => Ok(StorageOutcome::Value(None)),
            Some(value) => Ok(StorageOutcome::Value(Some(
                serde_json::from_value(value.clone()).map_err(|error| error.to_string())?,
            ))),
        },
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod testing {
    use serde_json::Value;
    use std::{cell::RefCell, future::Future, task::Context};

    pub(crate) const NOW: i64 = 60 * 86_400_000;
    type Handler = Box<dyn FnMut(Value) -> Value>;
    type StorageHandler = Box<dyn FnMut(Value) -> Value>;

    thread_local! {
        static HANDLER: RefCell<Option<Handler>> = const { RefCell::new(None) };
        static STORAGE_HANDLER: RefCell<Option<StorageHandler>> = const { RefCell::new(None) };
    }

    pub(super) fn respond(request: Value) -> Value {
        HANDLER.with_borrow_mut(|handler| {
            handler.as_mut().expect("no scripted database host")(request)
        })
    }

    pub(super) fn storage_respond(request: Value) -> Value {
        STORAGE_HANDLER
            .with_borrow_mut(|handler| handler.as_mut().expect("no scripted storage host")(request))
    }

    /// Runs one future against a scripted storage host. The handler receives
    /// the routed frame and returns {value: bytes | null}, {}, or {error}.
    pub(crate) fn run_storage<T>(
        handler: impl FnMut(Value) -> Value + 'static,
        future: impl Future<Output = T>,
    ) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                STORAGE_HANDLER.set(None);
            }
        }
        STORAGE_HANDLER.with_borrow_mut(|current| {
            assert!(current.is_none(), "nested scripted storage host");
            *current = Some(Box::new(handler));
        });
        let _reset = Reset;
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => {
                panic!("scripted storage host must complete synchronously")
            }
        }
    }

    pub(crate) fn run<T>(
        handler: impl FnMut(Value) -> Value + 'static,
        future: impl Future<Output = T>,
    ) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                HANDLER.set(None);
            }
        }
        HANDLER.with_borrow_mut(|current| {
            assert!(current.is_none(), "nested scripted database host");
            *current = Some(Box::new(handler));
        });
        let _reset = Reset;
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(std::task::Waker::noop());
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => value,
            std::task::Poll::Pending => {
                panic!("scripted database host must complete synchronously")
            }
        }
    }
}

#[cfg(not(all(test, not(target_arch = "wasm32"))))]
pub(crate) fn start_log(frame: Vec<u8>) -> Option<js_sys::Promise> {
    host_log(frame).ok()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) fn start_log(frame: Vec<u8>) -> Option<js_sys::Promise> {
    let _ = testing::respond(serde_json::from_slice(&frame).unwrap());
    None
}
