#![cfg(all(feature = "sdk", feature = "conformance"))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chickinfry::client::{Client, conformance};
use chickinfry_conformance_driver::protocol;

#[path = "../../tests/common/mod.rs"]
mod common;
// Exercise the driver's actual accumulator, without copying its retention formula.
#[path = "../src/transport.rs"]
mod transport;

#[derive(Clone, Copy, Default)]
struct Count {
    enabled: bool,
    live: isize,
    peak: isize,
}

thread_local! {
    // Only the synchronous SDK thread is counted; peer and test-harness threads are excluded.
    static COUNT: Cell<Count> = const { Cell::new(Count { enabled: false, live: 0, peak: 0 }) };
}

struct Allocator;

fn record(old: usize, new: usize) {
    let _ = COUNT.try_with(|slot| {
        let mut count = slot.get();
        if count.enabled {
            count.live = count
                .live
                .wrapping_add(new as isize)
                .wrapping_sub(old as isize);
            count.peak = count.peak.max(count.live);
            slot.set(count);
        }
    });
}

// SAFETY: System owns every allocation; accounting neither allocates nor unwinds.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record(0, layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record(0, layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        record(layout.size(), 0);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !pointer.is_null() {
            record(layout.size(), new_size);
        }
        pointer
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Pause(bool);

impl Pause {
    fn new() -> Self {
        Self(COUNT.with(|slot| {
            let count = slot.get();
            slot.set(Count {
                enabled: false,
                ..count
            });
            count.enabled
        }))
    }
}

impl Drop for Pause {
    fn drop(&mut self) {
        COUNT.with(|slot| {
            slot.set(Count {
                enabled: self.0,
                ..slot.get()
            })
        });
    }
}

fn start_counting() {
    COUNT.with(|slot| {
        slot.set(Count {
            enabled: true,
            ..Count::default()
        })
    });
}

fn check_allocator() {
    let layout = Layout::from_size_align(4096, 8).unwrap();
    start_counting();
    let counts = unsafe {
        let pointer = std::alloc::alloc_zeroed(layout);
        assert!(!pointer.is_null());
        std::hint::black_box(pointer).write(7);
        let initial = COUNT.with(Cell::get);
        let pointer = std::alloc::realloc(pointer, layout, 8192);
        assert!(!pointer.is_null());
        assert_eq!(std::hint::black_box(pointer).read(), 7);
        let grown = COUNT.with(Cell::get);
        std::alloc::dealloc(pointer, Layout::from_size_align(8192, 8).unwrap());
        (initial, grown, COUNT.with(Cell::get))
    };
    let _pause = Pause::new();
    assert_eq!((counts.0.live, counts.0.peak), (4096, 4096));
    assert_eq!((counts.1.live, counts.1.peak), (8192, 8192));
    assert_eq!((counts.2.live, counts.2.peak), (0, 8192));
}

#[test]
fn reported_retention_matches_independent_live_and_peak_allocations() {
    check_allocator();
    // Small request/HTTP objects are counted too. Allow 32 KiB for them, well below
    // either pinned 128 KiB I/O buffer, so omitting even one buffer cannot pass.
    const OVERHEAD: isize = 32 << 10;
    for (status, length) in [(200, (1 << 20) - 32), (200, (1 << 20) + 1), (302, 8 << 20)] {
        let empty = r#"{"wire_value":"","observed_at":"2026-01-02T03:04:05Z"}"#;
        let body = empty.replacen(
            r#""wire_value":"""#,
            &format!(r#""wire_value":"{}""#, "x".repeat(length - empty.len())),
            1,
        );
        assert_eq!(body.len(), length);
        let (origin, requests) =
            common::serve(&[common::response(&format!("HTTP/1.1 {status} Test"), &body)]);
        let sdk = chickinfry_client_plain::Client::new(
            Client::with_timeout(&origin, Duration::from_secs(5)).unwrap(),
        );
        let input = chickinfry_client_plain::client::ProbeEchoInput {
            wire_value: "ok".into(),
        };
        let mut log = transport::Log::default();
        log.start("c:oracle", false);
        let log = Arc::new(Mutex::new(log));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let observer = Arc::new({
            let log = log.clone();
            let samples = samples.clone();
            move |event| {
                let actual = COUNT.with(Cell::get);
                // Observer bookkeeping and JSON snapshots are not SDK body retention.
                let _pause = Pause::new();
                let mut log = log.lock().unwrap();
                log.event("c:oracle", &event);
                if let conformance::Event::Transport { .. } = event {
                    let snapshot = log.snapshot("c:oracle", 0).unwrap();
                    let reported = snapshot["events"]
                        .as_array()
                        .unwrap()
                        .last()
                        .unwrap()
                        .clone();
                    samples.lock().unwrap().push((actual, reported));
                }
            }
        });
        start_counting();
        let outcome = conformance::observe(observer, || sdk.probe.echo(&input));
        let _pause = Pause::new();
        log.lock().unwrap().finish("c:oracle");
        assert_eq!(outcome.is_ok(), status == 200 && length <= 1 << 20);
        let samples = samples.lock().unwrap();
        assert_eq!(samples.first().unwrap().1["phase"], "headers");
        assert!(
            samples
                .iter()
                .any(|(_, event)| event["phase"] == "reader-closed")
        );
        assert_eq!(
            samples.iter().any(|(_, event)| event["phase"] == "limit"),
            status == 200 && length > 1 << 20
        );
        for (actual, reported) in samples.iter() {
            for (field, measured) in [
                ("retainedBytes", actual.live),
                ("peakRetainedBytes", actual.peak),
            ] {
                let reported_bytes =
                    reported[field].as_i64().expect("complete byte measurement") as isize;
                assert!(
                    measured.abs_diff(reported_bytes) <= OVERHEAD as usize,
                    "status={status} length={length} phase={} {field}: allocator={measured} driver={reported_bytes} overhead={OVERHEAD}",
                    reported["phase"],
                );
            }
        }
        let (actual, reported) = samples.last().unwrap();
        eprintln!(
            "status={status} length={length} samples={} allocatorPeak={} driverPeak={}",
            samples.len(),
            actual.peak,
            reported["peakRetainedBytes"],
        );
        let request = requests.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(request.path, "/probe.echo");
        assert!(request.authorization.is_none());
        assert_eq!(request.body, r#"{"wire_value":"ok"}"#);
    }
}
