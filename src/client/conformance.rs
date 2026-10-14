//! Opt-in observations for the conformance process, absent from customer builds.

use std::cell::RefCell;
use std::sync::Arc;

/// Observed transitions; credential values remain inside the test process.
#[derive(Clone)]
pub enum Event {
    Entered,
    OriginalRejected { access_token: String },
    RefreshParticipation { leader: bool, refresh_token: String },
    Sending,
    Transmitting,
    Response { status: u16 },
    ResponseComplete,
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
        ureq::unversioned::resolver::DefaultResolver::default(),
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
        Ok(transport.map(Observed))
    }
}

#[derive(Debug)]
struct Observed<T>(T);

impl<T: Transport> Transport for Observed<T> {
    fn buffers(&mut self) -> &mut dyn Buffers {
        self.0.buffers()
    }
    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        if amount > 0 {
            emit(Event::Transmitting);
        }
        self.0.transmit_output(amount, timeout)
    }
    fn maybe_await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.0.maybe_await_input(timeout)
    }
    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        self.0.await_input(timeout)
    }
    fn is_open(&mut self) -> bool {
        self.0.is_open()
    }
    fn is_tls(&self) -> bool {
        self.0.is_tls()
    }
}
