//! Shared Chickinfry runtime for Rust application servers compiled to
//! WebAssembly. Project generators emit typed models, the required handler
//! trait, dispatch, and repositories; this crate owns the generic transport,
//! host database ABI, and ORM execution semantics.

extern crate self as chickinfry;

#[path = "auth/private/database.rs"]
mod private_auth;

pub mod auth;
pub mod database;
#[cfg(not(target_arch = "wasm32"))]
pub mod client;
pub mod host;
pub mod orm;
pub mod server;

pub use serde;
pub use serde_json;
pub use wasm_bindgen;

pub use server::{read_input, write_output, DispatchError, InvalidInputError, OperationError};

use std::sync::OnceLock;

/// Runtime configuration delivered once by the engine glue before the first
/// request. Values arrive over the same private binding channel used by the
/// other server languages; none of them are read from process environment.
#[derive(Default, PartialEq, Eq, serde::Deserialize)]
pub struct RuntimeConfig {
    #[serde(default, rename = "databaseUrl")]
    pub database_url: Option<String>,
    #[serde(default)]
    pub secrets: std::collections::BTreeMap<String, String>,
}

static CONFIG: OnceLock<RuntimeConfig> = OnceLock::new();

/// Installs the runtime configuration. The engine glue calls this once after
/// module initialization; later calls are ignored so a stale request cannot
/// replace the binding set.
#[wasm_bindgen::prelude::wasm_bindgen(js_name = chikConfigure)]
pub fn chik_configure(config: Vec<u8>) -> Result<(), wasm_bindgen::JsValue> {
    let parsed: RuntimeConfig = serde_json::from_slice(&config)
        .map_err(|_| wasm_bindgen::JsValue::from_str("Invalid runtime bindings."))?;
    if let Some(current) = CONFIG.get() {
        if current != &parsed {
            return Err(wasm_bindgen::JsValue::from_str("Runtime bindings have already been initialized."));
        }
        return Ok(());
    }
    CONFIG.set(parsed).map_err(|_| wasm_bindgen::JsValue::from_str("Runtime bindings could not be initialized."))
}

pub(crate) fn config() -> &'static RuntimeConfig {
    CONFIG.get_or_init(RuntimeConfig::default)
}
