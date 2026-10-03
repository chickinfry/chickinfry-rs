//! Database ports. A pooled port executes queries on the request connection
//! pool; a transaction port leases one dedicated connection for the duration
//! of one transaction. Post-completion reuse is rejected by the host lease and
//! nested transactions cannot be expressed: the generated transaction database
//! type simply has no transaction method.

use crate::host::{self, HostRequest};
use crate::server::OperationError;

/// Per-request pooled port routed by the glue through the request identifier.
#[derive(Clone, Copy)]
pub struct DatabasePort {
    pub(crate) rid: u64,
}

impl DatabasePort {
    pub(crate) fn new(rid: u64) -> Self {
        Self { rid }
    }

    pub(crate) async fn query(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, OperationError> {
        let response = host::call(HostRequest::query(self.rid, sql, params))
            .await
            .map_err(|_| OperationError::internal())?;
        match response.error {
            Some(code) => Err(OperationError::database(code)),
            None => Ok(response.rows),
        }
    }
}

/// Transaction-bound port over one leased connection. The port is consumed by
/// commit or rollback, so a completed transaction cannot run further work.
#[derive(Clone, Copy)]
pub struct TransactionPort {
    pub(crate) rid: u64,
    pub(crate) lease: u64,
}

impl TransactionPort {
    pub async fn begin(port: DatabasePort) -> Result<Self, OperationError> {
        let response = host::call(HostRequest::begin(port.rid))
            .await
            .map_err(|_| OperationError::internal())?;
        match (response.error, response.lease) {
            (None, Some(lease)) => Ok(Self { rid: port.rid, lease }),
            _ => Err(OperationError::internal()),
        }
    }

    pub(crate) async fn query(
        &self,
        sql: &str,
        params: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, OperationError> {
        let response = host::call(HostRequest::exec(self.rid, self.lease, sql, params))
            .await
            .map_err(|_| OperationError::internal())?;
        match response.error {
            Some(code) => Err(OperationError::database(code)),
            None => Ok(response.rows),
        }
    }

    /// Commits the transaction. An uncertain commit outcome surfaces as a
    /// generic failure; callers must never retry the transaction automatically.
    pub async fn commit(self) -> Result<(), OperationError> {
        let response = host::call(HostRequest::finish(self.rid, "commit", self.lease))
            .await
            .map_err(|_| OperationError::internal())?;
        match response.error {
            None => Ok(()),
            Some(_) => Err(OperationError::internal()),
        }
    }

    /// Rolls back quietly; a broken connection already aborted the work.
    pub async fn rollback(self) {
        let _ = host::call(HostRequest::finish(self.rid, "rollback", self.lease)).await;
    }
}
