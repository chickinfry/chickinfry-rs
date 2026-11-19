use super::{Bridge, Error, Handle, Result, protocol, typed_call};
use chickinfry::client::ClientError;
use chickinfry::realtime::{RealtimeControl, RealtimeProbe, SubscribeOptions, with_realtime_probe};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    error::Error as _,
    fmt,
    io::Write,
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex, Weak},
    thread,
    time::Duration,
};

#[derive(Debug)]
struct DecodeFailure;
impl fmt::Display for DecodeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("customer decode failed")
    }
}
impl std::error::Error for DecodeFailure {}

#[derive(Debug)]
struct RecoveryFailure(DecodeFailure);
impl fmt::Display for RecoveryFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("customer recovery failed")
    }
}
impl std::error::Error for RecoveryFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

struct Facts {
    events: Vec<String>,
    values: Map<String, Value>,
    points: HashSet<String>,
    held: HashSet<String>,
    frames: HashMap<String, Box<dyn FnOnce() + Send>>,
    holding: bool,
    stopped: bool,
    callbacks: usize,
    gaps: usize,
    control: Option<RealtimeControl>,
}

pub(super) struct Trial {
    handle: Arc<Handle>,
    origin: String,
    state: Mutex<Facts>,
    changed: Condvar,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl Trial {
    pub(super) fn new(handle: Arc<Handle>) -> Arc<Self> {
        let origin = handle.transport.origin().to_owned();
        let mut values = Map::new();
        for name in [
            "callbackStarts",
            "callbackCompletions",
            "callbackOverlapAtMost",
            "dbReads",
            "pendingReads",
            "activeRenewalWatchers",
            "deliveredAfterEnd",
            "publicWireOperations",
            "terminalErrors",
            "staleFramesHeld",
            "staleFramesDiscarded",
        ] {
            values.insert(name.into(), json!(0));
        }
        values.insert("state".into(), json!("ready"));
        Arc::new(Self {
            handle,
            origin,
            state: Mutex::new(Facts {
                events: vec![],
                values,
                points: HashSet::new(),
                held: HashSet::new(),
                frames: HashMap::new(),
                holding: false,
                stopped: false,
                callbacks: 0,
                gaps: 0,
                control: None,
            }),
            changed: Condvar::new(),
            worker: Mutex::new(None),
        })
    }

    fn increase(state: &mut Facts, name: &str) {
        state.values.insert(
            name.into(),
            json!(state.values[name].as_u64().unwrap_or(0) + 1),
        );
    }

    fn point(&self, state: &mut Facts, name: &str) {
        state.points.insert(name.to_owned());
        self.changed.notify_all();
    }

    fn hold(&self, name: &str, point: &str) {
        let mut state = self.state.lock().unwrap();
        state.held.insert(name.to_owned());
        self.point(&mut state, point);
        let _guard = self
            .changed
            .wait_while(state, |s| !s.stopped && s.held.contains(name))
            .unwrap();
    }

    fn hooks(self: &Arc<Self>) -> RealtimeProbe {
        let origin = self.origin.clone();
        let point = Arc::downgrade(self);
        let dispatch = Arc::downgrade(self);
        let control = Arc::downgrade(self);
        RealtimeProbe {
            endpoint: Box::new(move |candidate| {
                let expected = origin
                    .strip_prefix("http://127.0.0.1:")
                    .map(|port| format!("ws://127.0.0.1:{port}/realtime"));
                if expected.as_deref() != Some(candidate) {
                    return Err(ClientError::new("internal", None, false));
                }
                Ok(candidate.to_owned())
            }),
            point: Box::new(move |name| {
                if let Some(t) = point.upgrade() {
                    let mut state = t.state.lock().unwrap();
                    match name {
                        "gap" => {
                            state.gaps += 1;
                            let point = if state.gaps == 1 {
                                "gap-received"
                            } else {
                                "gap-received-again"
                            };
                            t.point(&mut state, point);
                        }
                        "demand" => t.point(&mut state, "subscribed"),
                        "overflow" => t.point(&mut state, "overflow-received"),
                        "recovered" => t.point(&mut state, "recovered"),
                        "discarded" => Self::increase(&mut state, "staleFramesDiscarded"),
                        _ => {}
                    }
                }
            }),
            dispatch: Box::new(move |raw, receive| {
                if let Some(t) = dispatch.upgrade() {
                    let frame: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
                    let kind = frame
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let mut state = t.state.lock().unwrap();
                    if state.holding
                        && matches!(kind, "ready" | "event")
                        && !state.frames.contains_key(kind)
                    {
                        state.frames.insert(kind.into(), receive);
                        Self::increase(&mut state, "staleFramesHeld");
                        if state.frames.len() == 2 {
                            t.point(&mut state, "stale-frames-held");
                        }
                        return;
                    }
                }
                receive();
            }),
            control: Box::new(move |value| {
                if let Some(t) = control.upgrade() {
                    t.state.lock().unwrap().control = Some(value);
                }
            }),
        }
    }

    pub(super) fn start(self: &Arc<Self>, args: &Value) -> Result<Value> {
        let channel = protocol::string(args, "channel")?;
        let mode = protocol::string(args, "onGap")?;
        let event = protocol::string(args, "eventHandler")?;
        if channel != "orders"
            || !matches!(mode, "hold" | "absent" | "fail" | "cause")
            || !matches!(event, "normal" | "hold-a")
            || protocol::string(args, "transport")? != "plain"
        {
            return Err(Error::driver("invalid_args"));
        }
        let mut worker = self.worker.lock().unwrap();
        if worker.is_some() {
            return Err(Error::driver("invalid_args"));
        }
        let trial = self.clone();
        let abort = matches!(mode, "fail" | "cause");
        let gap = mode != "absent";
        let held_a = event == "hold-a";
        *worker = Some(thread::spawn(move || trial.consume(gap, abort, held_a)));
        Ok(json!({"accepted":true}))
    }

    fn consume(self: Arc<Self>, gap: bool, abort: bool, held_a: bool) {
        let error = self.receive(gap, abort, held_a);
        let mut state = self.state.lock().unwrap();
        if let Err((failure, phase)) = error {
            if failure.code == "canceled" {
                state.values.insert("state".into(), json!("canceled"));
            } else {
                state.values.insert("state".into(), json!("error"));
                state.values.insert("errorCode".into(), json!(failure.code));
                state.values.insert(
                    "httpStatus".into(),
                    json!(failure.operation_error.as_ref().map(|op| op.status)),
                );
                state.values.insert("errorPhase".into(), json!(phase));
                Self::increase(&mut state, "terminalErrors");
                if let Some(cause) = failure
                    .source()
                    .and_then(|source| source.downcast_ref::<RecoveryFailure>())
                {
                    state
                        .values
                        .insert("errorType".into(), json!("RecoveryFailure"));
                    let expected = cause
                        .source()
                        .is_some_and(|source| source.is::<DecodeFailure>());
                    state
                        .values
                        .insert("causeType".into(), json!("DecodeFailure"));
                    state
                        .values
                        .insert("causePreserved".into(), json!(expected));
                }
            }
        } else {
            state.values.insert("state".into(), json!("ended"));
        }
        self.point(&mut state, "ended");
    }

    fn receive(
        self: &Arc<Self>,
        gap: bool,
        abort: bool,
        held_a: bool,
    ) -> std::result::Result<(), (ClientError, &'static str)> {
        let Bridge::Plain(client) = &self.handle.sdk else {
            return Err((ClientError::new("internal", None, false), "subscribe"));
        };
        let mut options = SubscribeOptions::default();
        if gap {
            let trial: Weak<Self> = Arc::downgrade(self);
            options.on_gap = Some(Box::new(move |_| {
                let Some(t) = trial.upgrade() else {
                    return Ok(());
                };
                let count = {
                    let mut state = t.state.lock().unwrap();
                    Self::increase(&mut state, "callbackStarts");
                    state.callbacks += 1;
                    let old = state.values["callbackOverlapAtMost"].as_u64().unwrap_or(0);
                    let overlap = old.max(state.callbacks as u64);
                    state
                        .values
                        .insert("callbackOverlapAtMost".into(), json!(overlap));
                    state.values["callbackStarts"].as_u64().unwrap_or(0)
                };
                let result = (|| {
                    typed_call(&t.handle, "probe.list", &json!({}))?;
                    Self::increase(&mut t.state.lock().unwrap(), "dbReads");
                    if abort {
                        let error: Box<dyn std::error::Error + Send + Sync> =
                            Box::new(RecoveryFailure(DecodeFailure));
                        return Err(error);
                    }
                    t.hold(
                        "gap",
                        if count == 1 {
                            "gap-entered"
                        } else {
                            "gap-entered-again"
                        },
                    );
                    Self::increase(&mut t.state.lock().unwrap(), "callbackCompletions");
                    Ok(())
                })();
                t.state.lock().unwrap().callbacks -= 1;
                result
            }));
        }
        let mut sub = with_realtime_probe(self.hooks(), || {
            client.realtime.subscribe("orders", options)
        })
        .map_err(|e| (e, "subscribe"))?;
        for event in sub.events() {
            let event = event.map_err(|e| (e, "events"))?;
            let Some(id) = event
                .payload
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| matches!(*id, "A" | "B" | "C" | "overflow"))
            else {
                return Err((ClientError::new("internal", None, false), "events"));
            };
            {
                let mut state = self.state.lock().unwrap();
                if state.values["state"] != "ready" {
                    Self::increase(&mut state, "deliveredAfterEnd");
                }
                state.events.push(id.into());
            }
            if id == "A" && held_a {
                self.hold("event-a", "event-a-entered");
            }
            self.point(
                &mut self.state.lock().unwrap(),
                &format!("event-{}-complete", id.to_ascii_lowercase()),
            );
        }
        Ok(())
    }

    pub(super) fn stop(&self, canceled: bool) {
        let control = {
            let mut state = self.state.lock().unwrap();
            state.stopped = true;
            let control = state.control.clone();
            self.changed.notify_all();
            control
        };
        if let Some(control) = control {
            control.stop(canceled);
        }
    }

    pub(super) fn command(&self, command: &str, args: &Value) -> Result<Value> {
        let timeout = Duration::from_millis(protocol::millis(args, "timeoutMs")?);
        match command {
            "realtime.observe" => {
                let point = protocol::string(args, "point")?;
                let state = self.state.lock().unwrap();
                let (state, _) = self
                    .changed
                    .wait_timeout_while(state, timeout, |s| {
                        point != "snapshot" && !s.points.contains(point)
                    })
                    .unwrap();
                if point != "snapshot" && !state.points.contains(point) {
                    return Err(Error::driver("deadline_exceeded"));
                }
                let event_ids = state.events.clone();
                let mut values = state.values.clone();
                let control = state.control.clone();
                drop(state);
                if let Some(control) = control {
                    let [pending, watchers, budgets, _, _] = control.inspect();
                    values.insert("pendingReads".into(), json!(pending));
                    values.insert("activeRenewalWatchers".into(), json!(watchers));
                    values.insert("budgetResets".into(), json!(budgets.saturating_sub(1)));
                    if budgets > 0 {
                        values.insert("reprepareBudgetMs".into(), json!(30000));
                    }
                }
                values.insert("eventIds".into(), json!(event_ids));
                return Ok(json!({"facts":values}));
            }
            "realtime.release" => {
                let point = protocol::string(args, "point")?;
                if !self.state.lock().unwrap().held.remove(point) {
                    return Err(Error::driver("invalid_args"));
                }
                self.changed.notify_all();
            }
            "realtime.unsubscribe" | "realtime.cancel" => {
                let canceled = command == "realtime.cancel";
                self.stop(canceled);
                self.stop(canceled);
                let state = self.state.lock().unwrap();
                let (state, _) = self
                    .changed
                    .wait_timeout_while(state, timeout, |s| !s.points.contains("ended"))
                    .unwrap();
                if !state.points.contains("ended") {
                    return Err(Error::driver("deadline_exceeded"));
                }
            }
            "realtime.hold-dispatch" => self.state.lock().unwrap().holding = true,
            "realtime.release-dispatch" => {
                let frames = {
                    let mut state = self.state.lock().unwrap();
                    state.holding = false;
                    std::mem::take(&mut state.frames)
                };
                for receive in frames.into_values() {
                    receive();
                }
            }
            "realtime.second-consumer" => {
                let control = self
                    .state
                    .lock()
                    .unwrap()
                    .control
                    .clone()
                    .ok_or_else(|| Error::driver("invalid_reference"))?;
                let before = control.inspect()[3];
                let proof = ownership_rejection()?;
                let after = control.inspect()[3];
                let mut state = self.state.lock().unwrap();
                state.values.extend(proof);
                state
                    .values
                    .insert("newConnections".into(), json!(after.saturating_sub(before)));
            }
            _ => return Err(Error::driver("unimplemented")),
        }
        Ok(json!({"accepted":true}))
    }
}

fn ownership_rejection() -> Result<Map<String, Value>> {
    const SOURCE: &str = "use chickinfry::realtime::RealtimeSubscription;\npub fn collect_twice(mut sub: RealtimeSubscription) { let mut a=sub.events(); let mut b=sub.events(); let _=(a.next(),b.next()); }\n";
    let fail = || Error::driver("driver_failed");
    let rustc = option_env!("RUSTC").ok_or_else(fail)?;
    // Cargo writes dependencies into the coordinator's intermediate build directory.
    let build = std::env::var_os("CARGO_BUILD_BUILD_DIR").ok_or_else(fail)?;
    let deps = std::path::PathBuf::from(build).join("debug/deps");
    let library = deps.join("libchickinfry.rlib");
    if !library.is_file() {
        return Err(fail());
    }
    let output = std::env::temp_dir().join("realtime-ownership.rmeta");
    let mut process = Command::new(rustc)
        .args([
            "--crate-name",
            "realtime_ownership",
            "--crate-type",
            "lib",
            "--edition",
            "2024",
            "--emit",
            "metadata",
            "--error-format",
            "short",
            "-",
        ])
        .arg("--extern")
        .arg(format!("chickinfry={}", library.display()))
        .arg("-L")
        .arg(format!("dependency={}", deps.display()))
        .arg("-o")
        .arg(&output)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| fail())?;
    process
        .stdin
        .take()
        .ok_or_else(fail)?
        .write_all(SOURCE.as_bytes())
        .map_err(|_| fail())?;
    let completed = process.wait_with_output().map_err(|_| fail())?;
    let _ = std::fs::remove_file(output);
    let diagnostic = String::from_utf8_lossy(&completed.stderr);
    if completed.status.success() || !diagnostic.contains("E0499") {
        return Err(fail());
    }
    let mut values = Map::new();
    values.insert("exclusiveConsumption".into(), json!(true));
    values.insert("consumptionRejection".into(), json!("compile"));
    values.insert(
        "sourceSHA256".into(),
        json!(format!("{:x}", Sha256::digest(SOURCE.as_bytes()))),
    );
    values.insert(
        "compileRejectionSHA256".into(),
        json!(format!("{:x}", Sha256::digest(&completed.stderr))),
    );
    values.insert(
        "compilerExitCode".into(),
        json!(completed.status.code().ok_or_else(fail)?),
    );
    Ok(values)
}
