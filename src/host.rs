//! Host ABI. The engine glue provides the single imported entry point that
//! executes database operations through the shared PostgreSQL port of the
//! runtime host. Requests and responses are UTF-8 JSON frames routed by the
//! per-request identifier assigned by the glue.

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen]
unsafe extern "C" {
    #[wasm_bindgen(js_namespace = __chik)]
    pub safe fn db(request: Vec<u8>) -> js_sys::Promise;
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

pub(crate) async fn call(request: HostRequest<'_>) -> Result<HostResponse, String> {
    let payload = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
    let value = wasm_bindgen_futures::JsFuture::from(db(payload))
        .await
        .map_err(|error| format_host_rejection(error))?;
    let bytes = js_sys::Uint8Array::from(value).to_vec();
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

/// Cryptographically strong random bytes from the host. Used for opaque
/// session and refresh tokens; only their digests are ever persisted.
pub fn random_bytes(length: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0u8; length];
    getrandom::getrandom(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn format_host_rejection(error: crate::wasm_bindgen::JsValue) -> String {
    let text = error.as_string();
    match text {
        Some(message) => message,
        None => "the database host rejected the operation".to_string(),
    }
}
