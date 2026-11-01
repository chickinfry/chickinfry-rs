use std::{cell::RefCell, future::Future, rc::Rc, sync::Once};

struct RequestLogs {
    rid: u64,
    pending: RefCell<Vec<wasm_bindgen_futures::JsFuture>>,
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<RequestLogs>>> = const { RefCell::new(None) };
}

struct Logger;
static LOGGER: Logger = Logger;
static INSTALL: Once = Once::new();

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Debug && CURRENT.with_borrow(Option::is_some)
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        CURRENT.with_borrow(|current| {
            if let Some(current) = current {
                let level = match record.level() {
                    log::Level::Debug => "debug",
                    log::Level::Info => "info",
                    log::Level::Warn => "warn",
                    log::Level::Error => "error",
                    log::Level::Trace => return,
                };
                let frame = serde_json::json!({
                    "rid": current.rid, "level": level, "message": record.args().to_string(),
                });
                if let Ok(bytes) = serde_json::to_vec(&frame) {
                    if let Some(promise) = crate::host::start_log(bytes) {
                        current
                            .pending
                            .borrow_mut()
                            .push(wasm_bindgen_futures::JsFuture::from(promise));
                    }
                }
            }
        });
    }

    fn flush(&self) {}
}

// Request futures share one WASM thread; scope each poll so suspended requests cannot inherit another rid.
pub(crate) async fn scope<T>(rid: u64, future: impl Future<Output = T>) -> T {
    INSTALL.call_once(|| {
        if log::set_logger(&LOGGER).is_ok() {
            log::set_max_level(log::LevelFilter::Debug);
        }
    });
    struct Restore(Option<Rc<RequestLogs>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CURRENT.set(self.0.take());
        }
    }
    let current = Rc::new(RequestLogs {
        rid,
        pending: RefCell::new(Vec::new()),
    });
    let mut future = std::pin::pin!(future);
    let output = std::future::poll_fn(|cx| {
        let _restore = Restore(CURRENT.replace(Some(current.clone())));
        future.as_mut().poll(cx)
    })
    .await;
    let pending = current.pending.take();
    for promise in pending {
        let _ = promise.await;
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::testing;
    use serde_json::json;
    use std::{cell::RefCell, rc::Rc};

    #[test]
    fn standard_logs_keep_request_frames_and_ignore_host_failure() {
        let frames = Rc::new(RefCell::new(Vec::new()));
        let observed = frames.clone();
        let output = testing::run(
            move |frame| {
                observed.borrow_mut().push(frame);
                json!({"error":"log_failed"})
            },
            async {
                log::info!("outside request");
                let output = scope(7, async {
                    log::debug!("debug {}", 1);
                    log::info!("info");
                    log::warn!("warn");
                    log::error!("error");
                    log::trace!("unsupported");
                    42
                })
                .await;
                log::error!("after request");
                output
            },
        );
        assert_eq!(output, 42);
        assert_eq!(
            *frames.borrow(),
            vec![
                json!({"rid":7,"level":"debug","message":"debug 1"}),
                json!({"rid":7,"level":"info","message":"info"}),
                json!({"rid":7,"level":"warn","message":"warn"}),
                json!({"rid":7,"level":"error","message":"error"}),
            ]
        );
    }
    #[test]
    fn suspended_requests_restore_their_own_log_context() {
        let frames = Rc::new(RefCell::new(Vec::new()));
        let observed = frames.clone();
        testing::run(
            move |frame| {
                observed.borrow_mut().push(frame);
                json!({})
            },
            async {
                let mut first = std::pin::pin!(scope(10, async {
                    log::info!("before suspension");
                    let mut ready = false;
                    std::future::poll_fn(|cx| {
                        if ready {
                            return std::task::Poll::Ready(());
                        }
                        ready = true;
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    })
                    .await;
                    log::info!("after suspension");
                }));
                let mut second = std::pin::pin!(scope(20, async {
                    log::info!("other request");
                }));
                std::future::poll_fn(|cx| {
                    assert!(first.as_mut().poll(cx).is_pending());
                    log::error!("between requests");
                    assert!(second.as_mut().poll(cx).is_ready());
                    assert!(first.as_mut().poll(cx).is_ready());
                    std::task::Poll::Ready(())
                })
                .await;
            },
        );
        assert_eq!(
            *frames.borrow(),
            vec![
                json!({"rid":10,"level":"info","message":"before suspension"}),
                json!({"rid":20,"level":"info","message":"other request"}),
                json!({"rid":10,"level":"info","message":"after suspension"}),
            ]
        );
    }
}
