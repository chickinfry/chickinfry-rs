pub mod protocol;
mod session;

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Write};
#[cfg(feature = "conformance")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use chickinfry::client::{Client, ClientError};
use serde_json::{Value, json};

use protocol::{Error, Message, Request, Response, Result};
use session::{Credentials, Store};

#[cfg(feature = "sdk")]
use chickinfry_client_plain as sdk;

struct Handle {
    transport: Client,
    store: Option<Arc<Store>>,
    #[cfg(feature = "sdk")]
    sdk: sdk::Client,
}

impl Handle {
    fn new(transport: Client, store: Option<Arc<Store>>) -> Self {
        Self {
            #[cfg(feature = "sdk")]
            sdk: sdk::Client::new(transport.clone()),
            transport,
            store,
        }
    }
}

#[derive(Clone)]
struct Barrier {
    #[cfg(feature = "conformance")]
    reference: String,
    point: String,
    participants: HashSet<String>,
    arrivals: HashSet<String>,
}

struct Pending {
    sender: mpsc::Sender<Result<Value>>,
    barrier: String,
}

#[derive(Default)]
struct PendingState {
    closed: bool,
    requests: HashMap<String, Pending>,
}

struct State<W> {
    output: Mutex<W>,
    refs: Arc<Credentials>,
    clients: Mutex<HashMap<String, Arc<Handle>>>,
    stores: Mutex<HashMap<String, Arc<Store>>>,
    barriers: Mutex<HashMap<String, Barrier>>,
    pending: Mutex<PendingState>,
    #[cfg(feature = "conformance")]
    next_id: AtomicU64,
    failed: AtomicBool,
}

fn capabilities() -> Vec<&'static str> {
    let mut values = vec!["client.create", "client.copy", "session.store"];
    if cfg!(all(feature = "sdk", feature = "conformance")) {
        values.push("client.call");
    }
    if cfg!(all(feature = "sdk", feature = "conformance")) {
        values.extend(["barrier", "session.trace"]);
    }
    values
}

impl<W: Write + Send + 'static> State<W> {
    fn new(output: W, refs: Arc<Credentials>) -> Self {
        Self {
            output: Mutex::new(output),
            refs,
            clients: Mutex::new(HashMap::new()),
            stores: Mutex::new(HashMap::new()),
            barriers: Mutex::new(HashMap::new()),
            pending: Mutex::new(PendingState::default()),
            #[cfg(feature = "conformance")]
            next_id: AtomicU64::new(1),
            failed: AtomicBool::new(false),
        }
    }

    fn output(&self, value: &Value) -> Result<()> {
        let line = serde_json::to_vec(value).map_err(|_| Error::driver("driver_failed"))?;
        if line.len() > protocol::MAX_LINE {
            return Err(Error::driver("protocol_violation"));
        }
        if self.refs.contains_secret(
            std::str::from_utf8(&line).map_err(|_| Error::driver("driver_failed"))?,
        ) {
            return Err(Error::driver("driver_failed"));
        }
        let mut output = self.output.lock().unwrap();
        output
            .write_all(&line)
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.flush())
            .map_err(|_| Error::driver("driver_failed"))
    }

    fn reply(&self, id: &str, outcome: Result<Value>) {
        let value = match outcome {
            Ok(value) => json!({"id": id, "result": value, "error": null}),
            Err(error) => json!({"id": id, "result": null, "error": error}),
        };
        if self.output(&value).is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
    }

    fn store(&self, args: &Value) -> Result<Arc<Store>> {
        self.stores
            .lock()
            .unwrap()
            .get(protocol::reference(args, "storeRef")?)
            .cloned()
            .ok_or_else(|| Error::driver("invalid_reference"))
    }

    fn client(&self, reference: &str) -> Result<Arc<Handle>> {
        self.clients
            .lock()
            .unwrap()
            .get(reference)
            .cloned()
            .ok_or_else(|| Error::driver("invalid_reference"))
    }

    fn execute(self: &Arc<Self>, request: &Request) -> Result<Value> {
        let args = &request.args;
        match request.command.as_str() {
            "client.create" => {
                let reference = protocol::reference(args, "clientRef")?;
                if self.clients.lock().unwrap().contains_key(reference) {
                    return Err(Error::driver("protocol_violation"));
                }
                let mut transport = Client::with_timeout(
                    protocol::string(args, "origin")?,
                    Duration::from_millis(protocol::millis(args, "requestTimeoutMs")?),
                )
                .map_err(sdk_error)?;
                if args.get("storeRef").is_some() && args.get("bearerRef").is_some() {
                    return Err(Error::driver("invalid_args"));
                }
                let store = if args.get("storeRef").is_some() {
                    let store = self.store(args)?;
                    store.bind(transport.origin());
                    transport = transport.with_session(store.clone()).map_err(sdk_error)?;
                    Some(store)
                } else {
                    None
                };
                if args.get("bearerRef").is_some() {
                    transport = transport
                        .with_bearer(&self.refs.get(protocol::reference(args, "bearerRef")?)?)
                        .map_err(sdk_error)?;
                }
                self.clients
                    .lock()
                    .unwrap()
                    .insert(reference.into(), Arc::new(Handle::new(transport, store)));
                Ok(json!({"clientRef": reference}))
            }
            "client.copy" => {
                let reference = protocol::reference(args, "clientRef")?;
                if self.clients.lock().unwrap().contains_key(reference) {
                    return Err(Error::driver("protocol_violation"));
                }
                let source = self.client(protocol::reference(args, "sourceClientRef")?)?;
                let token = self.refs.get(protocol::reference(args, "bearerRef")?)?;
                let transport = source.transport.with_bearer(&token).map_err(sdk_error)?;
                self.clients
                    .lock()
                    .unwrap()
                    .insert(reference.into(), Arc::new(Handle::new(transport, None)));
                Ok(json!({"clientRef": reference}))
            }
            "session.store.create" => {
                let reference = protocol::reference(args, "storeRef")?;
                if self.stores.lock().unwrap().contains_key(reference) {
                    return Err(Error::driver("protocol_violation"));
                }
                let store = Arc::new(Store::new(self.refs.clone()));
                if args.get("accessRef").is_some() || args.get("refreshRef").is_some() {
                    store.write(
                        protocol::reference(args, "accessRef")?,
                        protocol::reference(args, "refreshRef")?,
                    )?;
                }
                let revision = store.read(false)?["revision"].clone();
                self.stores.lock().unwrap().insert(reference.into(), store);
                Ok(json!({"storeRef": reference, "revision": revision}))
            }
            "session.store.write" => self.store(args)?.write(
                protocol::reference(args, "accessRef")?,
                protocol::reference(args, "refreshRef")?,
            ),
            "session.store.read" => {
                let trace = args
                    .get("includeTrace")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| Error::driver("invalid_args"))?;
                if trace && !cfg!(all(feature = "sdk", feature = "conformance")) {
                    return Err(Error::driver("unimplemented"));
                }
                self.store(args)?.read(trace)
            }
            "barrier.arm" => {
                if !cfg!(all(feature = "sdk", feature = "conformance")) {
                    return Err(Error::driver("unimplemented"));
                }
                let reference = protocol::reference(args, "barrierRef")?;
                let point = protocol::string(args, "point")?;
                if !["sdk-entered", "both-originals-rejected", "refresh-joined"].contains(&point) {
                    return Err(Error::driver("unimplemented"));
                }
                let participants = args
                    .get("participants")
                    .and_then(Value::as_array)
                    .ok_or_else(|| Error::driver("invalid_args"))?;
                let mut ids = HashSet::new();
                for id in participants {
                    let id = id
                        .as_str()
                        .filter(|v| v.starts_with("c:") && v.len() > 2 && protocol::name(v))
                        .ok_or_else(|| Error::driver("invalid_args"))?;
                    if !ids.insert(id.to_owned()) {
                        return Err(Error::driver("protocol_violation"));
                    }
                }
                if ids.is_empty() {
                    return Err(Error::driver("invalid_args"));
                }
                let mut barriers = self.barriers.lock().unwrap();
                if barriers.contains_key(reference)
                    || barriers.values().any(|b| {
                        b.point == point && b.participants.iter().any(|id| ids.contains(id))
                    })
                {
                    return Err(Error::driver("protocol_violation"));
                }
                barriers.insert(
                    reference.into(),
                    Barrier {
                        #[cfg(feature = "conformance")]
                        reference: reference.into(),
                        point: point.into(),
                        participants: ids,
                        arrivals: HashSet::new(),
                    },
                );
                Ok(json!({"barrierRef": reference, "state": "armed"}))
            }
            "client.call" => self.call(request),
            _ => Err(Error::driver("unimplemented")),
        }
    }

    fn call(self: &Arc<Self>, request: &Request) -> Result<Value> {
        if !cfg!(all(feature = "sdk", feature = "conformance")) {
            return Err(Error::driver("unimplemented"));
        }
        let handle = self.client(protocol::reference(&request.args, "clientRef")?)?;
        let operation = protocol::string(&request.args, "operation")?;
        if operation != "probe.echo" {
            return Err(Error::driver("unimplemented"));
        }
        let mut input = request
            .args
            .get("input")
            .cloned()
            .ok_or_else(|| Error::driver("invalid_args"))?;
        if let Some(refs) = request.args.get("inputRefs") {
            for (field, reference) in refs
                .as_object()
                .ok_or_else(|| Error::driver("invalid_args"))?
            {
                let reference = reference
                    .as_str()
                    .filter(|v| protocol::name(v))
                    .ok_or_else(|| Error::driver("invalid_args"))?;
                input
                    .as_object_mut()
                    .ok_or_else(|| Error::driver("invalid_args"))?
                    .insert(field.clone(), self.refs.get(reference)?.into());
            }
        }
        if input.get("wire_value").and_then(Value::as_str).is_none() {
            return Err(Error::driver("unimplemented"));
        }
        if let Some(refs) = request.args.get("outputRefs") {
            let refs = refs
                .as_object()
                .ok_or_else(|| Error::driver("invalid_args"))?;
            for (field, name) in refs {
                if !["wire_value", "observed_at"].contains(&field.as_str())
                    || !name.as_str().is_some_and(protocol::name)
                {
                    return Err(Error::driver("invalid_args"));
                }
            }
        }
        let deadline =
            Instant::now() + Duration::from_millis(protocol::millis(&request.args, "timeoutMs")?);
        let observations = Arc::new(Mutex::new(CallObservations::default()));
        let observer = observations.clone();
        let state = self.clone();
        let id = request.id.clone();
        let case_id = protocol::reference(&request.args, "caseId")?.to_owned();
        let store = handle.store.clone();
        #[cfg(feature = "conformance")]
        let execute = || {
            chickinfry::client::conformance::observe(
                Arc::new(move |event| {
                    use chickinfry::client::conformance::Event;
                    let mut facts = json!({"observed": true});
                    let point = match event {
                        Event::Entered => Some("sdk-entered"),
                        Event::OriginalRejected { access_token } => {
                            facts["accessRef"] = json!(state.refs.find(&access_token));
                            Some("both-originals-rejected")
                        }
                        Event::RefreshParticipation {
                            leader,
                            refresh_token,
                        } => {
                            if let Some(store) = &store {
                                store.participation(&id, leader, &refresh_token);
                            }
                            facts["refreshRef"] = json!(state.refs.find(&refresh_token));
                            facts["leader"] = json!(leader);
                            if leader { None } else { Some("refresh-joined") }
                        }
                        Event::Sending => {
                            let mut o = observer.lock().unwrap();
                            o.outcome_unknown = false;
                            o.http_status = None;
                            None
                        }
                        Event::Transmitting => {
                            observer.lock().unwrap().outcome_unknown = true;
                            None
                        }
                        Event::Response { status } => {
                            observer.lock().unwrap().http_status = Some(status);
                            None
                        }
                        Event::ResponseComplete => {
                            observer.lock().unwrap().outcome_unknown = false;
                            None
                        }
                    };
                    if let Some(point) = point
                        && let Err(error) = state.arrive(&id, &case_id, point, facts, deadline)
                    {
                        observer.lock().unwrap().error = Some(error);
                        // Stop this execution after a failed observation; never make an extra request.
                        std::panic::panic_any(ObservationFailed);
                    }
                }),
                || typed_call(&handle, operation, &input),
            )
        };
        #[cfg(not(feature = "conformance"))]
        let execute = || {
            let _ = (&observer, &state, &id, &case_id, &store, deadline);
            typed_call(&handle, operation, &input)
        };
        let outcome = session::with_call(&request.id, || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(execute))
        });
        let observed = observations.lock().unwrap();
        if let Some(error) = &observed.error {
            return Err(error.clone());
        }
        let outcome = outcome.map_err(|_| Error::driver("driver_failed"))?;
        let mut output = outcome.map_err(|error| {
            let mut error = sdk_error(error);
            if error.http_status.is_none() {
                error.http_status = observed.http_status;
            }
            error.outcome_unknown = observed.outcome_unknown;
            error
        })?;
        let mut refs = serde_json::Map::new();
        if let Some(names) = request.args.get("outputRefs") {
            for (field, name) in names
                .as_object()
                .ok_or_else(|| Error::driver("invalid_args"))?
            {
                let name = name
                    .as_str()
                    .filter(|v| protocol::name(v))
                    .ok_or_else(|| Error::driver("invalid_args"))?;
                let value = output
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::driver("invalid_args"))?;
                self.refs.register(name, value)?;
                refs.insert(field.clone(), name.into());
                output.as_object_mut().unwrap().remove(field);
            }
        }
        self.refs.sanitize(&mut output);
        Ok(json!({"output": output, "credentialRefs": refs, "httpStatus": observed.http_status}))
    }

    #[cfg(feature = "conformance")]
    fn arrive(
        &self,
        call_id: &str,
        case_id: &str,
        point: &str,
        facts: Value,
        deadline: Instant,
    ) -> Result<()> {
        let (barrier, id, receiver) = {
            let mut pending = self.pending.lock().unwrap();
            if pending.closed {
                return Err(Error::driver("driver_failed"));
            }
            let mut barriers = self.barriers.lock().unwrap();
            let Some(barrier) = barriers
                .values_mut()
                .find(|b| b.point == point && b.participants.contains(call_id))
            else {
                return Ok(());
            };
            if !barrier.arrivals.insert(call_id.into()) {
                return Err(Error::driver("protocol_violation"));
            }
            let barrier = barrier.clone();
            let id = format!("d:{}", self.next_id.fetch_add(1, Ordering::SeqCst));
            let (sender, receiver) = mpsc::channel();
            pending.requests.insert(
                id.clone(),
                Pending {
                    sender,
                    barrier: barrier.reference.clone(),
                },
            );
            (barrier, id, receiver)
        };
        self.output(&json!({"id": id, "command": "barrier.arrive", "args": {
                "barrierRef": barrier.reference, "callId": call_id, "point": point, "facts": facts,
                "caseId": case_id, "timeoutMs": deadline.saturating_duration_since(Instant::now()).as_millis().max(1),
        }}))?;
        let outcome = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| Error::driver("deadline_exceeded"));
        self.pending.lock().unwrap().requests.remove(&id);
        outcome??;
        Ok(())
    }

    fn release(&self, response: Response) -> Result<()> {
        let pending = self
            .pending
            .lock()
            .unwrap()
            .requests
            .remove(&response.id)
            .ok_or_else(|| Error::driver("protocol_violation"))?;
        let outcome = if response.error.is_null() {
            protocol::fields(
                &response.result,
                &["barrierRef", "state", "sequence"],
                false,
            )?;
            let barriers = self.barriers.lock().unwrap();
            let barrier = barriers
                .get(&pending.barrier)
                .ok_or_else(|| Error::driver("protocol_violation"))?;
            if response.result.get("barrierRef").and_then(Value::as_str) != Some(&pending.barrier)
                || response.result.get("state").and_then(Value::as_str) != Some("released")
                || response
                    .result
                    .get("sequence")
                    .and_then(Value::as_u64)
                    .filter(|v| *v > 0)
                    .is_none()
                || barrier.arrivals != barrier.participants
            {
                return Err(Error::driver("protocol_violation"));
            }
            Ok(response.result)
        } else {
            Err(serde_json::from_value(response.error)
                .map_err(|_| Error::driver("protocol_violation"))?)
        };
        pending
            .sender
            .send(outcome)
            .map_err(|_| Error::driver("protocol_violation"))
    }

    fn cancel(&self) {
        let mut state = self.pending.lock().unwrap();
        state.closed = true;
        for (_, pending) in state.requests.drain() {
            let _ = pending.sender.send(Err(Error::driver("driver_failed")));
        }
    }
}

#[derive(Default)]
struct CallObservations {
    http_status: Option<u16>,
    outcome_unknown: bool,
    error: Option<Error>,
}
#[cfg(feature = "conformance")]
struct ObservationFailed;

fn sdk_error(error: ClientError) -> Error {
    let (code, status) = match error {
        ClientError::Operation(e) => (Some(e.code), Some(e.status)),
        ClientError::Protocol(_) => (None, None),
    };
    Error {
        kind: "sdk".into(),
        code,
        http_status: status,
        outcome_unknown: false,
    }
}

fn typed_call(
    handle: &Handle,
    operation: &str,
    input: &Value,
) -> std::result::Result<Value, ClientError> {
    #[cfg(feature = "sdk")]
    if operation == "probe.echo" {
        let client = &handle.sdk;
        let input = sdk::client::ProbeEchoInput {
            wire_value: input["wire_value"]
                .as_str()
                .expect("validated fixture input")
                .into(),
        };
        let output = client.probe.echo(&input)?;
        return Ok(json!({"wire_value": output.wire_value, "observed_at": output.observed_at}));
    }
    let _ = (handle, operation, input);
    Err(ClientError::Protocol(
        "fixture operation is unavailable".into(),
    ))
}

fn validate(request: &Request) -> Result<()> {
    let fields: &[&str] = match request.command.as_str() {
        "handshake" => &[
            "protocolVersions",
            "runId",
            "requiredCapabilities",
            "target",
        ],
        "client.create" => &[
            "clientRef",
            "origin",
            "storeRef",
            "bearerRef",
            "requestTimeoutMs",
        ],
        "client.copy" => &["sourceClientRef", "clientRef", "bearerRef"],
        "client.call" => &["clientRef", "operation", "input", "inputRefs", "outputRefs"],
        "session.store.create" => &["storeRef", "accessRef", "refreshRef", "origin", "recordRef"],
        "session.store.write" => &["storeRef", "accessRef", "refreshRef", "recordRef"],
        "session.store.read" => &["storeRef", "includeTrace"],
        "barrier.arm" => &["barrierRef", "point", "participants"],
        _ => return Err(Error::driver("unimplemented")),
    };
    protocol::fields(&request.args, fields, request.command != "handshake")?;
    // The coordinator does not yet convey the selected plain/auth fixture.
    if request
        .args
        .get("caseId")
        .and_then(Value::as_str)
        .is_some_and(|id| ["C-08", "C-09", "C-10"].contains(&id))
        || request.args.get("recordRef").is_some()
    {
        return Err(Error::driver("unimplemented"));
    }
    Ok(())
}

fn handshake(args: &Value) -> Result<Value> {
    let target = args
        .get("target")
        .ok_or_else(|| Error::driver("invalid_args"))?;
    protocol::fields(target, &["language", "role", "environment"], false)?;
    if protocol::string(target, "language")? != "rust"
        || protocol::string(target, "role")? != "sdk"
        || protocol::string(target, "environment")? != "native"
    {
        return Err(Error::driver("unimplemented"));
    }
    let versions = args
        .get("protocolVersions")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::driver("invalid_args"))?;
    if versions.iter().any(|v| v.as_u64().is_none()) {
        return Err(Error::driver("invalid_args"));
    }
    if !versions.contains(&json!(1)) {
        return Err(Error::driver("protocol_mismatch"));
    }
    protocol::reference(args, "runId")?;
    let required = args
        .get("requiredCapabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::driver("invalid_args"))?;
    let capabilities = capabilities();
    for value in required {
        let name = value
            .as_str()
            .ok_or_else(|| Error::driver("invalid_args"))?;
        if !capabilities.contains(&name) {
            return Err(Error::driver("unimplemented"));
        }
    }
    Ok(
        json!({"protocolVersion": 1, "driverVersion": env!("CARGO_PKG_VERSION"), "capabilities": capabilities}),
    )
}

/// Runs the internal protocol; the caller owns the inherited credential pipe.
pub fn run<R: BufRead, W: Write + Send + 'static>(
    mut input: R,
    output: W,
    credentials: &mut impl BufRead,
) -> Result<()> {
    let refs = Arc::new(Credentials::default());
    refs.load(credentials)?;
    let state = Arc::new(State::new(output, refs));
    let mut ids = HashSet::new();
    let mut negotiated = false;
    let mut case = None;
    let mut workers = Vec::new();
    let outcome = (|| {
        while let Some(line) = protocol::line(&mut input)? {
            if state.failed.load(Ordering::SeqCst) {
                return Err(Error::driver("driver_failed"));
            }
            match protocol::message(&line)? {
                Message::Response(response) => state.release(response)?,
                Message::Request(request) => {
                    if state.refs.contains_secret(&request.id) || !ids.insert(request.id.clone()) {
                        return Err(Error::driver("protocol_violation"));
                    }
                    if !negotiated {
                        if request.command != "handshake" {
                            state.reply(&request.id, Err(Error::driver("protocol_violation")));
                            return Err(Error::driver("protocol_violation"));
                        }
                        let outcome = validate(&request).and_then(|_| handshake(&request.args));
                        negotiated = outcome.is_ok();
                        state.reply(&request.id, outcome.clone());
                        outcome?;
                        continue;
                    }
                    if request.command == "handshake" {
                        return Err(Error::driver("protocol_violation"));
                    }
                    match validate(&request) {
                        Err(e) if e.code.as_deref() == Some("unimplemented") => {
                            state.reply(&request.id, Err(e));
                            continue;
                        }
                        Err(e) => {
                            state.reply(&request.id, Err(e.clone()));
                            return Err(e);
                        }
                        Ok(()) => {}
                    }
                    let case_id = protocol::reference(&request.args, "caseId")?;
                    protocol::millis(&request.args, "timeoutMs")?;
                    if case.as_ref().is_some_and(|v| v != case_id) {
                        return Err(Error::driver("protocol_violation"));
                    }
                    case.get_or_insert_with(|| case_id.to_owned());
                    if request.command == "client.call" {
                        let state = state.clone();
                        workers.push(std::thread::spawn(move || {
                            let outcome = state.execute(&request);
                            state.reply(&request.id, outcome);
                        }));
                    } else {
                        let outcome = state.execute(&request);
                        let fatal = outcome
                            .as_ref()
                            .err()
                            .filter(|e| e.code.as_deref() == Some("protocol_violation"))
                            .cloned();
                        state.reply(&request.id, outcome);
                        if let Some(error) = fatal {
                            return Err(error);
                        }
                    }
                }
            }
        }
        if !negotiated {
            return Err(Error::driver("protocol_violation"));
        }
        Ok(())
    })();
    state.cancel();
    for worker in workers {
        if worker.join().is_err() {
            state.failed.store(true, Ordering::SeqCst);
        }
    }
    outcome?;
    if state.failed.load(Ordering::SeqCst) {
        return Err(Error::driver("driver_failed"));
    }
    Ok(())
}

#[cfg(all(test, not(feature = "conformance"), feature = "sdk"))]
#[path = "../../tests/common/mod.rs"]
mod common;

#[cfg(all(test, not(feature = "conformance"), feature = "sdk"))]
#[test]
fn default_off_sdk_entry_and_refresh_have_no_observation_path() {
    let access = "E".repeat(43);
    let refresh = "F".repeat(43);
    let rotated = json!({
        "access_token":"G".repeat(43), "refresh_token":"H".repeat(43),
        "expires_at":"2026-01-02T00:00:00Z", "refresh_expires_at":"2026-01-03T00:00:00Z",
        "user_id":"user", "session_id":"session",
    })
    .to_string();
    let (origin, requests) = common::serve(&[
        common::response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
        common::response("HTTP/1.1 200 OK", &rotated),
        common::response(
            "HTTP/1.1 200 OK",
            r#"{"wire_value":"ok","observed_at":"2026-01-02T03:04:05Z"}"#,
        ),
    ]);
    let refs = Arc::new(Credentials::default());
    refs.register("access", &access).unwrap();
    refs.register("refresh", &refresh).unwrap();
    let store = Arc::new(Store::new(refs));
    store.write("access", "refresh").unwrap();
    store.bind(&origin);
    let transport = Client::with_timeout(&origin, Duration::from_secs(1))
        .unwrap()
        .with_session(store.clone())
        .unwrap();
    let handle = Handle::new(transport, Some(store));
    let output = typed_call(&handle, "probe.echo", &json!({"wire_value":"ok"})).unwrap();
    assert_eq!(output["wire_value"], "ok");
    for (path, bearer) in [
        ("/probe.echo", Some(format!("Bearer {access}"))),
        ("/auth.refresh", None),
        ("/probe.echo", Some(format!("Bearer {}", "G".repeat(43)))),
    ] {
        let request = requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(request.path, path);
        assert_eq!(request.authorization, bearer);
        if path == "/auth.refresh" {
            assert_eq!(
                serde_json::from_str::<Value>(&request.body).unwrap()["refresh_token"],
                refresh
            );
        }
    }
    // Inspect the debug test that executed the SDK, independently of release stripping.
    let symbols = std::process::Command::new("nm")
        .arg("-C")
        .arg(std::env::current_exe().unwrap())
        .output()
        .expect("nm must be available to inspect the executed test binary");
    assert!(
        symbols.status.success(),
        "nm could not read the symbol table"
    );
    let symbols = String::from_utf8(symbols.stdout).unwrap();
    assert!(
        symbols.contains("chickinfry::client::"),
        "demangled runtime symbols must be readable"
    );
    assert!(
        !symbols.contains("chickinfry::client::conformance::"),
        "default runtime contains an observation path"
    );
}

#[cfg(all(test, feature = "conformance", feature = "sdk"))]
#[test]
fn sdk_entry_after_eof_cancellation_cannot_register_a_pending_arrival() {
    let state = Arc::new(State::new(Vec::new(), Arc::new(Credentials::default())));
    state.execute(&Request {
        id: "c:create".into(), command: "client.create".into(),
        args: json!({"clientRef":"client","origin":"http://127.0.0.1:9","requestTimeoutMs":1000}),
    }).unwrap();
    state
        .execute(&Request {
            id: "c:arm".into(),
            command: "barrier.arm".into(),
            args: json!({"barrierRef":"entry","point":"sdk-entered","participants":["c:late"]}),
        })
        .unwrap();
    let before_entry = Arc::new(std::sync::Barrier::new(2));
    let enter = Arc::new(std::sync::Barrier::new(2));
    let (done, result) = mpsc::channel();
    let worker = std::thread::spawn({
        let state = state.clone();
        let before_entry = before_entry.clone();
        let enter = enter.clone();
        move || {
            before_entry.wait();
            enter.wait();
            done.send(state.execute(&Request {
                id: "c:late".into(), command: "client.call".into(),
                args: json!({"caseId":"C-09","timeoutMs":10000,"clientRef":"client","operation":"probe.echo","input":{"wire_value":"ok"}}),
            })).unwrap();
        }
    });
    before_entry.wait();
    state.cancel();
    enter.wait();
    let error = result
        .recv_timeout(Duration::from_secs(1))
        .expect("late entry must not wait for the command deadline")
        .unwrap_err();
    assert_eq!(error.code.as_deref(), Some("driver_failed"));
    assert!(state.pending.lock().unwrap().requests.is_empty());
    assert!(state.output.lock().unwrap().is_empty());
    worker.join().unwrap();
}
