//! Opt-in observations for the conformance process, absent from customer builds.

use std::cell::RefCell;
use std::sync::Arc;

#[cfg(test)]
#[path = "../../tests/common/mod.rs"]
mod common;

/// Observed transitions; credential values remain inside the test process.
#[derive(Clone)]
pub enum Event {
    Entered,
    OriginalRejected {
        access_token: String,
    },
    RefreshParticipation {
        leader: bool,
        refresh_ref: usize,
    },
    Resolving,
    Sending {
        refresh: bool,
    },
    Transmitting,
    AwaitingResponse,
    Response {
        status: u16,
    },
    ResponseComplete,
    TransportClosed,
    SessionClearing,
    SessionSaved,
    #[cfg(test)]
    SessionClearCompared,
    Transport {
        phase: &'static str,
        bytes: usize,
        retained: Option<usize>,
    },
}

type Observer = Arc<dyn Fn(Event) + Send + Sync>;

thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = RefCell::new(None);
}

/// Observes one synchronous SDK execution on this thread and restores its scope.
pub fn observe<T>(observer: Observer, operation: impl FnOnce() -> T) -> T {
    struct Restore(Option<Observer>);
    impl Drop for Restore {
        fn drop(&mut self) {
            OBSERVER.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(OBSERVER.with(|slot| slot.replace(Some(observer))));
    operation()
}

pub(super) fn emit(event: Event) {
    let observer = OBSERVER.with(|slot| slot.borrow().clone());
    if let Some(observer) = observer {
        observer(event);
    }
}

pub(super) fn agent(config: ureq::config::Config) -> ureq::Agent {
    use ureq::unversioned::transport::{Connector, DefaultConnector};
    ureq::Agent::with_parts(
        config,
        DefaultConnector::default().chain(ObserveTransport),
        ObserveResolver,
    )
}

use ureq::unversioned::transport::{Buffers, ConnectionDetails, Connector, NextTimeout, Transport};

#[derive(Debug)]
struct ObserveTransport;

impl<T: Transport> Connector<T> for ObserveTransport {
    type Out = Observed<T>;
    fn connect(
        &self,
        _: &ConnectionDetails,
        transport: Option<T>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        Ok(transport.map(|transport| Observed(Some(transport))))
    }
}

#[derive(Debug)]
struct Observed<T>(Option<T>);

impl<T> Drop for Observed<T> {
    fn drop(&mut self) {
        drop(self.0.take());
        emit(Event::TransportClosed);
    }
}

impl<T: Transport> Transport for Observed<T> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.0.as_mut().unwrap().buffers()
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        if amount > 0 {
            emit(Event::Transmitting);
        }
        self.0.as_mut().unwrap().transmit_output(amount, timeout)
    }
    fn maybe_await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        emit(Event::AwaitingResponse);
        self.0.as_mut().unwrap().maybe_await_input(timeout)
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        emit(Event::AwaitingResponse);
        self.0.as_mut().unwrap().await_input(timeout)
    }
    fn is_open(&mut self) -> bool {
        self.0.as_mut().unwrap().is_open()
    }
    fn is_tls(&self) -> bool {
        self.0.as_ref().unwrap().is_tls()
    }
}

#[derive(Debug)]
struct ObserveResolver;

impl ureq::unversioned::resolver::Resolver for ObserveResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        emit(Event::Resolving);
        ureq::unversioned::resolver::DefaultResolver::default().resolve(uri, config, timeout)
    }
}

#[cfg(test)]
#[test]
fn receiving_preserves_standard_read_sizes_capacity_and_bytes() {
    use std::io::Read;
    struct Input {
        remaining: usize,
        chunk: usize,
        sizes: Vec<usize>,
        initialized: Vec<Vec<u8>>,
    }
    impl Read for Input {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.sizes.push(buffer.len());
            if self.remaining < 128 {
                self.initialized
                    .push(buffer.iter().take(64).copied().collect());
            }
            let count = self.remaining.min(self.chunk).min(buffer.len());
            buffer.fill(b'x');
            self.remaining -= count;
            Ok(count)
        }
    }
    for length in [0, 1, 31, 32, 33, 96, 8192, 1048576, 1048577, 2097152] {
        for chunk in [1, 2, 3, 4, 5, 6, 7, 32, 8192, 65536] {
            if length > 128 && chunk < 7 {
                continue;
            }
            let make = || {
                Input {
                    remaining: length,
                    chunk,
                    sizes: Vec::new(),
                    initialized: Vec::new(),
                }
                .take(1048577)
            };
            let (mut previous, mut current) = (make(), make());
            let (mut expected, mut actual) = (Vec::new(), Vec::new());
            previous.read_to_end(&mut expected).unwrap();
            super::read_response(&mut current, &mut actual).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                actual.capacity(),
                expected.capacity(),
                "length={length} chunk={chunk}"
            );
            assert_eq!(
                current.get_ref().sizes,
                previous.get_ref().sizes,
                "length={length} chunk={chunk}"
            );
            assert_eq!(
                current.get_ref().initialized,
                previous.get_ref().initialized,
                "initialized spare bytes length={length} chunk={chunk}"
            );
        }
    }
}

#[cfg(test)]
#[test]
fn memory_session_comparison_and_deletion_exclude_concurrent_writes() {
    use super::{MemorySessionStore, SessionCredentials};
    use std::sync::mpsc;
    use std::time::Duration;
    let record = |value: &str| SessionCredentials {
        access_token: value.repeat(43),
        refresh_token: value.repeat(43),
        expires_at: "2099-01-01T00:00:00Z".into(),
        refresh_expires_at: "2099-01-08T00:00:00Z".into(),
        user_id: "user".into(),
        session_id: "session".into(),
    };
    let old = record("P");
    let new = record("Q");
    let store = Arc::new(MemorySessionStore::new("http://127.0.0.1:9", Some(old.clone())).unwrap());
    let (entered, writing) = mpsc::channel();
    let (finished, written) = mpsc::channel();
    let writer = Arc::new(std::sync::Mutex::new(None));
    let writing = std::sync::Mutex::new(writing);
    let written = Arc::new(std::sync::Mutex::new(written));
    let removed = observe(
        Arc::new({
            let store = store.clone();
            let writer = writer.clone();
            let new = new.clone();
            let written = written.clone();
            move |event| {
                if matches!(event, Event::SessionClearCompared) {
                    assert!(
                        store.credentials.try_lock().is_err(),
                        "comparison must retain the deletion lock"
                    );
                    let (store, new, entered, finished) = (
                        store.clone(),
                        new.clone(),
                        entered.clone(),
                        finished.clone(),
                    );
                    *writer.lock().unwrap() = Some(std::thread::spawn(move || {
                        entered.send(()).unwrap();
                        store.write(new).unwrap();
                        finished.send(()).unwrap();
                    }));
                    writing
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap();
                    assert!(matches!(
                        written
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_millis(20)),
                        Err(mpsc::RecvTimeoutError::Timeout)
                    ));
                }
            }
        }),
        || store.clear(&old),
    );
    assert!(removed);
    writer.lock().unwrap().take().unwrap().join().unwrap();
    assert!(store.read().as_ref() == Some(&new));
    assert!(!store.clear(&old));
    assert!(store.clear(&new));
    assert!(store.read().is_none());
}

#[cfg(test)]
#[test]
fn delayed_successful_refresh_preserves_concurrent_login_or_deletion() {
    use super::{Client, MemorySessionStore, SessionCredentials};
    use std::sync::{Mutex, mpsc};
    use std::time::Duration;
    let record = |access: &str, refresh: &str| SessionCredentials {
        access_token: access.repeat(43),
        refresh_token: refresh.repeat(43),
        expires_at: "2099-01-01T00:00:00Z".into(),
        refresh_expires_at: "2099-01-08T00:00:00Z".into(),
        user_id: "user".into(),
        session_id: "session".into(),
    };
    for replace in [true, false] {
        let old = if replace {
            record("V", "W")
        } else {
            record("h", "j")
        };
        let login = record("X", "Y");
        let issued =
            serde_json::json!({"access_token":"Z".repeat(43),"refresh_token":"a".repeat(43),
            "expires_at":"2099-01-01T00:00:00Z","refresh_expires_at":"2099-01-08T00:00:00Z",
            "user_id":"user","session_id":"session"})
            .to_string();
        let (arrived, arrival) = mpsc::channel();
        let (release, released) = mpsc::channel();
        let released = Mutex::new(released);
        let (origin, requests) = common::serve_with(
            &[
                common::response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#),
                common::response("HTTP/1.1 200 OK", &issued),
            ],
            move |index| {
                if index == 1 {
                    arrived.send(()).unwrap();
                    released
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .unwrap();
                }
            },
        );
        let store = Arc::new(MemorySessionStore::new(&origin, Some(old.clone())).unwrap());
        let client = Client::with_timeout(&origin, Duration::from_secs(5))
            .unwrap()
            .with_session(store.clone())
            .unwrap();
        let call = std::thread::spawn(move || {
            client.invoke("probe.echo", &serde_json::json!({"wire_value":"ok"}))
        });
        arrival.recv_timeout(Duration::from_secs(5)).unwrap();
        if replace {
            store.write(login.clone()).unwrap();
        } else {
            assert!(store.clear(&old));
        }
        release.send(()).unwrap();
        assert!(call.join().unwrap().is_err());
        if replace {
            assert!(store.read().as_ref() == Some(&login));
        } else {
            assert!(store.read().is_none());
        }
        let original = requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(original.path, "/probe.echo");
        assert!(
            original.authorization.as_deref()
                == Some(format!("Bearer {}", old.access_token).as_str())
        );
        let refresh = requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(refresh.path, "/auth.refresh");
        assert!(refresh.authorization.is_none());
        assert!(
            serde_json::from_str::<serde_json::Value>(&refresh.body).unwrap()["refresh_token"]
                == old.refresh_token
        );
    }
}
