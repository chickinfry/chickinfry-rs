//! Realtime subscriptions for generated native clients.

use crate::client::{ClientError, Transport};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    error::Error,
    io::ErrorKind,
    net::{Shutdown, TcpStream, ToSocketAddrs},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant},
};
use tungstenite::{
    Error as SocketError, Message, WebSocket, client::IntoClientRequest, client_tls_with_config,
    protocol::WebSocketConfig, stream::MaybeTlsStream,
};

const BUDGET: Duration = Duration::from_secs(30);
const OPEN_LIMIT: Duration = Duration::from_secs(10);
const READ_LIMIT: Duration = Duration::from_millis(25);
const FRAME_LIMIT: usize = 66_560;
const RETRY_BASE: Duration = Duration::from_millis(500);

type Cause = Box<dyn Error + Send + Sync>;
type GapHandler = Box<dyn Fn(RealtimeGap) -> Result<(), Cause> + Send + Sync>;
type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

/// An application event in channel order.
pub struct RealtimeEvent {
    pub r#type: &'static str,
    pub channel: String,
    pub payload: Value,
}

/// A channel whose application state must be reloaded.
pub struct RealtimeGap {
    pub r#type: &'static str,
    pub channel: String,
}

/// Optional reload callback executed before delivery resumes after a gap.
#[derive(Default)]
pub struct SubscribeOptions {
    pub on_gap: Option<GapHandler>,
}

/// Uses the existing generated client's ticket and session transport.
pub struct RealtimeClient {
    transport: Arc<dyn Transport>,
}

#[doc(hidden)]
pub fn create_realtime_client(transport: Arc<dyn Transport>) -> RealtimeClient {
    RealtimeClient { transport }
}

impl RealtimeClient {
    /// Waits for the first ready connection using the native SDK's blocking call convention.
    pub fn subscribe(
        &self,
        channel: &str,
        options: SubscribeOptions,
    ) -> Result<RealtimeSubscription, ClientError> {
        if channel.is_empty() || channel.len() > 128 || channel.bytes().any(|b| b < 32 || b == 127)
        {
            return Err(client_error("invalid_argument"));
        }
        let probe = current_probe();
        let driver = Arc::new(Subscription {
            channel: channel.to_owned(),
            id: identifier().ok_or_else(|| client_error("internal"))?,
            transport: self.transport.clone(),
            on_gap: options.on_gap,
            probe,
            lock: Mutex::new(State {
                active: true,
                deadline: Some(Instant::now() + BUDGET),
                ..State::default()
            }),
            changed: Condvar::new(),
        });
        if let Some(probe) = &driver.probe {
            (probe.control)(RealtimeControl(driver.clone()));
        }
        let socket = driver.clone();
        thread::spawn(move || socket.run());
        let timeout = driver.clone();
        thread::spawn(move || timeout.watch_deadline());
        let renewal = driver.clone();
        thread::spawn(move || renewal.renew());
        let mut state = driver.lock.lock().expect("realtime state");
        while state.active && !state.first_ready {
            state = driver.changed.wait(state).expect("realtime state");
        }
        if !state.first_ready {
            return Err(state
                .failure
                .clone()
                .unwrap_or_else(|| client_error("canceled")));
        }
        drop(state);
        Ok(RealtimeSubscription {
            driver,
            used: false,
        })
    }
}

/// Owns one realtime subscription.
pub struct RealtimeSubscription {
    driver: Arc<Subscription>,
    used: bool,
}

impl RealtimeSubscription {
    /// Borrows the subscription for a single sequential iterator.
    ///
    /// ```compile_fail
    /// # use chickinfry::realtime::RealtimeSubscription;
    /// fn consume_twice(mut subscription: RealtimeSubscription) {
    ///     let mut first = subscription.events();
    ///     let mut second = subscription.events();
    ///     let _ = (first.next(), second.next());
    /// }
    /// ```
    pub fn events(&mut self) -> RealtimeEvents<'_> {
        let already_used = std::mem::replace(&mut self.used, true);
        RealtimeEvents {
            subscription: self,
            already_used,
            finished: false,
        }
    }

    /// Stops delivery and releases the socket. Repeated calls have no effect.
    pub fn unsubscribe(&self) {
        RealtimeControl(self.driver.clone()).stop_delivery(false);
    }
}

impl Drop for RealtimeSubscription {
    fn drop(&mut self) {
        self.unsubscribe();
    }
}

/// Sole iterator for a realtime subscription.
pub struct RealtimeEvents<'a> {
    subscription: &'a mut RealtimeSubscription,
    already_used: bool,
    finished: bool,
}

impl Iterator for RealtimeEvents<'_> {
    type Item = Result<RealtimeEvent, ClientError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if self.already_used {
            self.finished = true;
            return Some(Err(client_error("failed_precondition")));
        }
        let item = self.subscription.driver.next();
        self.finished = item.as_ref().is_none_or(Result::is_err);
        item
    }
}

impl Drop for RealtimeEvents<'_> {
    fn drop(&mut self) {
        if !self.already_used {
            self.subscription.unsubscribe();
        }
    }
}

type Dispatch = Box<dyn Fn(&str, Box<dyn FnOnce() + Send>) + Send + Sync>;
type Endpoint = Box<dyn Fn(&str) -> Result<String, ClientError> + Send + Sync>;

#[doc(hidden)]
pub struct RealtimeProbe {
    pub endpoint: Endpoint,
    pub point: Box<dyn Fn(&str) + Send + Sync>,
    pub dispatch: Dispatch,
    pub control: Box<dyn Fn(RealtimeControl) + Send + Sync>,
}

#[doc(hidden)]
#[derive(Clone)]
pub struct RealtimeControl(Arc<Subscription>);

impl RealtimeControl {
    fn stop_delivery(&self, canceled: bool) {
        let mut state = self.0.lock.lock().expect("realtime state");
        self.0
            .stop(&mut state, canceled.then(|| client_error("canceled")));
    }

    #[cfg(feature = "conformance")]
    pub fn stop(&self, canceled: bool) {
        self.stop_delivery(canceled);
    }

    #[cfg(feature = "conformance")]
    pub fn inspect(&self) -> [usize; 5] {
        let state = self.0.lock.lock().expect("realtime state");
        [
            usize::from(state.demand),
            state.watchers,
            state.loss_budgets,
            state.connections,
            usize::from(state.active),
        ]
    }
}

#[cfg(feature = "conformance")]
thread_local! { static PROBE: std::cell::RefCell<Option<Arc<RealtimeProbe>>> = const { std::cell::RefCell::new(None) }; }

#[cfg(feature = "conformance")]
#[doc(hidden)]
pub fn with_realtime_probe<T>(probe: RealtimeProbe, operation: impl FnOnce() -> T) -> T {
    struct Restore(Option<Arc<RealtimeProbe>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            PROBE.with(|slot| slot.replace(self.0.take()));
        }
    }
    let _restore = Restore(PROBE.with(|slot| slot.replace(Some(Arc::new(probe)))));
    operation()
}

fn current_probe() -> Option<Arc<RealtimeProbe>> {
    #[cfg(feature = "conformance")]
    {
        PROBE.with(|slot| slot.borrow().clone())
    }
    #[cfg(not(feature = "conformance"))]
    {
        None
    }
}

struct Connection {
    generation: usize,
    shutdown: TcpStream,
    confirmation: Option<String>,
    checkpoint: Option<String>,
    prepared: bool,
    outgoing: VecDeque<Value>,
}

struct Recovery {
    generation: usize,
    cursor: String,
    complete: bool,
    connection: usize,
}

#[derive(Default)]
struct State {
    active: bool,
    first_ready: bool,
    demand: bool,
    callback_running: bool,
    connection: Option<Connection>,
    recovery: Option<Recovery>,
    queue: VecDeque<(String, Value)>,
    last: String,
    deadline: Option<Instant>,
    failure: Option<ClientError>,
    connections: usize,
    recoveries: usize,
    loss_budgets: usize,
    watchers: usize,
}

struct Subscription {
    channel: String,
    id: String,
    on_gap: Option<GapHandler>,
    transport: Arc<dyn Transport>,
    probe: Option<Arc<RealtimeProbe>>,
    lock: Mutex<State>,
    changed: Condvar,
}

fn client_error(code: &str) -> ClientError {
    ClientError::new(code, None, false)
}

fn identifier() -> Option<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).ok()?;
    bytes[6] = (bytes[6] & 0xf) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let s = hex::encode(bytes);
    Some(format!(
        "{}-{}-{}-{}-{}",
        &s[..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..]
    ))
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn cursor(value: &str) -> bool {
    value.is_empty() || uuid(value)
}

fn endpoint(value: &str) -> Result<String, ClientError> {
    let id = value
        .strip_prefix("wss://")
        .and_then(|rest| rest.strip_suffix(".chickinfry.app/realtime"));
    if !id.is_some_and(uuid) {
        return Err(client_error("internal"));
    }
    Ok(value.to_owned())
}

fn dial(address: String) -> Option<(Socket, TcpStream)> {
    let request = address.into_client_request().ok()?;
    let host = request.uri().host()?;
    let port = request.uri().port_u16().unwrap_or(443);
    let end = Instant::now() + OPEN_LIMIT;
    for addr in (host, port).to_socket_addrs().ok()? {
        let remain = end.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            return None;
        }
        let Ok(stream) = TcpStream::connect_timeout(&addr, remain) else {
            continue;
        };
        stream.set_read_timeout(Some(remain)).ok()?;
        stream.set_write_timeout(Some(remain)).ok()?;
        let shutdown = stream.try_clone().ok()?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(FRAME_LIMIT))
            .max_frame_size(Some(FRAME_LIMIT));
        let (socket, _) = client_tls_with_config(request, stream, Some(config), None).ok()?;
        shutdown.set_read_timeout(Some(READ_LIMIT)).ok()?;
        shutdown
            .set_write_timeout(Some(Duration::from_secs(1)))
            .ok()?;
        return Some((socket, shutdown));
    }
    None
}

impl Subscription {
    fn point(&self, point: &str) {
        if let Some(probe) = &self.probe {
            (probe.point)(point);
        }
    }

    fn close_socket(&self, state: &mut State) {
        if let Some(c) = state.connection.take() {
            let _ = c.shutdown.shutdown(Shutdown::Both);
        }
        state.queue.clear();
        self.changed.notify_all();
    }

    fn stop(&self, state: &mut State, failure: Option<ClientError>) {
        if !state.active {
            return;
        }
        state.active = false;
        state.failure = failure;
        state.recovery = None;
        state.watchers = 0;
        self.close_socket(state);
    }

    fn start_budget(&self, state: &mut State) {
        if state.deadline.is_none() {
            state.deadline = Some(Instant::now() + BUDGET);
            if state.first_ready {
                state.loss_budgets += 1;
            }
            self.changed.notify_all();
        }
    }

    fn watch_deadline(&self) {
        let mut state = self.lock.lock().expect("realtime state");
        while state.active {
            if let Some(end) = state.deadline {
                let remaining = end.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    self.stop(&mut state, Some(client_error("deadline_exceeded")));
                    return;
                }
                state = self
                    .changed
                    .wait_timeout(state, remaining)
                    .expect("realtime state")
                    .0;
            } else {
                state = self.changed.wait(state).expect("realtime state");
            }
        }
    }

    fn pause(&self, duration: Duration) -> bool {
        let state = self.lock.lock().expect("realtime state");
        self.changed
            .wait_timeout_while(state, duration, |s| s.active)
            .expect("realtime state")
            .0
            .active
    }

    fn renew(&self) {
        let mut renew = false;
        loop {
            let result = self.transport.realtime_renewal(renew);
            let mut state = self.lock.lock().expect("realtime state");
            if !state.active {
                return;
            }
            match result {
                Ok(None) => return,
                Err(error) => {
                    self.stop(&mut state, Some(error));
                    return;
                }
                Ok(Some(delay)) => {
                    state.watchers = 1;
                    drop(state);
                    if !self.pause(delay) {
                        return;
                    }
                    renew = true;
                }
            }
        }
    }

    fn acknowledge(&self, state: &mut State) {
        if state.recovery.is_some() || !state.queue.is_empty() {
            return;
        }
        if let Some(c) = state.connection.as_mut().filter(|c| c.prepared) {
            if let Some(at) = c.checkpoint.take() {
                c.outgoing
                    .push_back(json!({"type":"ack","channel":self.channel,"cursor":at}));
            }
        }
    }

    fn next(self: &Arc<Self>) -> Option<Result<RealtimeEvent, ClientError>> {
        let mut state = self.lock.lock().expect("realtime state");
        loop {
            if !state.active {
                state.demand = false;
                return state.failure.take().map(Err);
            }
            if !state.demand {
                state.demand = true;
                self.point("demand");
            }
            self.recover(&mut state);
            if state.recovery.is_none() && state.connection.as_ref().is_some_and(|c| c.prepared) {
                if let Some((at, payload)) = state.queue.pop_front() {
                    state.last = at;
                    state.demand = false;
                    self.acknowledge(&mut state);
                    return Some(Ok(RealtimeEvent {
                        r#type: "event",
                        channel: self.channel.clone(),
                        payload,
                    }));
                }
            }
            state = self.changed.wait(state).expect("realtime state");
        }
    }

    fn recover(self: &Arc<Self>, state: &mut State) {
        let Some(recovery) = &state.recovery else {
            return;
        };
        if !state.active
            || recovery.complete
            || state.callback_running
            || (state.first_ready && !state.demand)
        {
            return;
        }
        let generation = recovery.generation;
        state.callback_running = true;
        let this = self.clone();
        thread::spawn(move || {
            let result = this.on_gap.as_ref().expect("registered gap callback")(RealtimeGap {
                r#type: "gap",
                channel: this.channel.clone(),
            });
            let mut state = this.lock.lock().expect("realtime state");
            state.callback_running = false;
            if state.active
                && state
                    .recovery
                    .as_ref()
                    .is_some_and(|r| r.generation == generation)
            {
                if let Err(cause) = result {
                    let mut error = client_error("unknown");
                    error.cause = Some(Arc::from(cause));
                    this.stop(&mut state, Some(error));
                    return;
                }
                let recovery = state.recovery.as_mut().expect("current gap");
                recovery.complete = true;
                state.last = recovery.cursor.clone();
                this.close_socket(&mut state);
            }
            this.recover(&mut state);
            this.changed.notify_all();
        });
    }

    fn gap(self: &Arc<Self>, state: &mut State, at: &str) {
        if self.on_gap.is_none() {
            self.stop(state, Some(client_error("data_loss")));
            return;
        }
        state.recoveries += 1;
        state.recovery = Some(Recovery {
            generation: state.recoveries,
            cursor: at.to_owned(),
            complete: false,
            connection: 0,
        });
        if let Some(connection) = state.connection.as_mut() {
            connection.prepared = false;
        }
        state.queue.clear();
        self.start_budget(state);
        self.point("gap");
        self.recover(state);
        self.changed.notify_all();
    }

    fn receive(self: &Arc<Self>, generation: usize, text: &str) {
        let mut state = self.lock.lock().expect("realtime state");
        if !state.active
            || state
                .connection
                .as_ref()
                .is_none_or(|c| c.generation != generation)
        {
            self.point("discarded");
            return;
        }
        if self.handle_frame(&mut state, generation, text).is_none() {
            self.stop(&mut state, Some(client_error("internal")));
        }
    }

    fn handle_frame(
        self: &Arc<Self>,
        state: &mut State,
        generation: usize,
        text: &str,
    ) -> Option<()> {
        let frame: Value = serde_json::from_str(text).ok()?;
        let kind = frame.get("type")?.as_str()?;
        if frame
            .get("channel")
            .map_or(kind != "error", |c| c.as_str() != Some(&self.channel))
        {
            return None;
        }
        match kind {
            "ready" => {
                let at = frame.get("cursor")?.as_str().filter(|v| cursor(v))?;
                let ack = match frame.get("acknowledge") {
                    None => false,
                    Some(bit) => bit.as_bool()?,
                };
                let c = state.connection.as_mut()?;
                c.checkpoint = ack.then(|| at.to_owned());
                if let Some(echo) = frame.get("confirmation") {
                    let echo = echo.as_str().filter(|v| uuid(v))?;
                    if c.confirmation.as_deref() != Some(echo) {
                        return Some(());
                    }
                } else {
                    if c.confirmation.is_none() {
                        let nonce = identifier()?;
                        c.outgoing.push_back(
                            json!({"type":"confirm","channel":self.channel,"confirmation":nonce}),
                        );
                        c.confirmation = Some(nonce);
                    }
                    return Some(());
                }
                if let Some(recovery) = &state.recovery {
                    if !recovery.complete || recovery.connection != generation {
                        return Some(());
                    }
                    state.recovery = None;
                    self.point("recovered");
                }
                c.prepared = true;
                state.first_ready = true;
                state.deadline = None;
                self.acknowledge(state);
            }
            "gap" => self.gap(state, frame.get("cursor")?.as_str().filter(|v| cursor(v))?),
            "event" => {
                let at = frame.get("cursor")?.as_str().filter(|v| uuid(v))?;
                let previous = frame.get("previous")?.as_str().filter(|v| cursor(v))?;
                let payload = frame.get("payload")?;
                if at == state.last || state.queue.iter().any(|(cursor, _)| cursor == at) {
                    return Some(());
                }
                let expected = state
                    .queue
                    .back()
                    .map(|(c, _)| c.as_str())
                    .or_else(|| state.recovery.as_ref().map(|r| r.cursor.as_str()))
                    .unwrap_or(&state.last);
                let full = state.queue.len() >= if self.probe.is_some() { 512 } else { 256 };
                if full || previous != expected {
                    if full {
                        self.point("overflow");
                    }
                    self.gap(state, at);
                } else {
                    state.queue.push_back((at.to_owned(), payload.clone()));
                }
            }
            "error" => {
                let wire = frame.get("error")?.as_str().filter(|s| {
                    !s.is_empty()
                        && s.len() <= 64
                        && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                })?;
                let code = match wire {
                    "unauthorized_channel" => "permission_denied",
                    "already_subscribed" => "internal",
                    "too_many_channels" => "resource_exhausted",
                    "replay_failed" | "realtime_unavailable" => "unavailable",
                    _ => "unknown",
                };
                self.stop(state, Some(client_error(code)));
            }
            _ => return None,
        }
        self.changed.notify_all();
        Some(())
    }

    fn ticket(&self) -> Result<String, ClientError> {
        let result = self.transport.invoke("realtime.ticket", &json!({}))?;
        let ticket = result
            .get("ticket")
            .and_then(Value::as_str)
            .filter(|v| uuid(v))
            .ok_or_else(|| client_error("internal"))?;
        let raw = result
            .get("endpoint")
            .and_then(Value::as_str)
            .ok_or_else(|| client_error("internal"))?;
        let address = if let Some(probe) = &self.probe {
            (probe.endpoint)(raw)?
        } else {
            endpoint(raw)?
        };
        Ok(format!("{address}?ticket={ticket}"))
    }

    fn run(self: Arc<Self>) {
        let mut backoff = RETRY_BASE;
        while self.lock.lock().expect("realtime state").active {
            match self.ticket() {
                Ok(address) => {
                    if let Some((socket, shutdown)) = dial(address) {
                        self.read_socket(socket, shutdown);
                        backoff = RETRY_BASE;
                    }
                }
                Err(error) => {
                    let mut state = self.lock.lock().expect("realtime state");
                    let retry = matches!(error.code.as_str(), "unavailable" | "deadline_exceeded")
                        && error.operation_error.is_none()
                        || error.operation_error.as_ref().is_some_and(|op| {
                            op.status == 429
                                || op.status >= 500
                                || op.status == 409 && !state.first_ready
                        });
                    if !retry {
                        self.stop(&mut state, Some(error));
                        return;
                    }
                }
            }
            if !self.pause(backoff) {
                return;
            }
            backoff = (backoff * 2).min(Duration::from_secs(5));
        }
    }

    fn read_socket(self: &Arc<Self>, mut socket: Socket, shutdown: TcpStream) {
        let generation = {
            let mut state = self.lock.lock().expect("realtime state");
            if !state.active {
                return;
            }
            state.connections += 1;
            let generation = state.connections;
            let start = if let Some(recovery) = state.recovery.as_mut() {
                if recovery.complete {
                    recovery.connection = generation;
                }
                recovery.cursor.clone()
            } else {
                state.last.clone()
            };
            let subscribe = json!({"type":"subscribe","channel":self.channel,"subscription":self.id,"cursor":start});
            state.connection = Some(Connection {
                generation,
                shutdown,
                confirmation: None,
                checkpoint: None,
                prepared: false,
                outgoing: VecDeque::from([subscribe]),
            });
            generation
        };
        loop {
            let frames = {
                let mut state = self.lock.lock().expect("realtime state");
                let Some(c) = state
                    .connection
                    .as_mut()
                    .filter(|c| c.generation == generation)
                else {
                    return;
                };
                std::mem::take(&mut c.outgoing)
            };
            if frames
                .into_iter()
                .any(|frame| socket.send(Message::text(frame.to_string())).is_err())
            {
                break;
            }
            match socket.read() {
                Ok(Message::Text(text)) => {
                    if let Some(probe) = &self.probe {
                        let this = self.clone();
                        let raw = text.to_string();
                        (probe.dispatch)(
                            text.as_str(),
                            Box::new(move || this.receive(generation, &raw)),
                        );
                    } else {
                        self.receive(generation, text.as_str());
                    }
                }
                Ok(Message::Close(_)) => break,
                Ok(Message::Binary(_)) | Err(SocketError::Capacity(_)) => {
                    let mut state = self.lock.lock().expect("realtime state");
                    if state
                        .connection
                        .as_ref()
                        .is_some_and(|c| c.generation == generation)
                    {
                        self.stop(&mut state, Some(client_error("internal")));
                    }
                    return;
                }
                Err(SocketError::Io(error))
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => break,
                _ => {}
            }
        }
        let mut state = self.lock.lock().expect("realtime state");
        if state
            .connection
            .as_ref()
            .is_some_and(|c| c.generation == generation)
        {
            self.close_socket(&mut state);
            self.start_budget(&mut state);
        }
    }
}
