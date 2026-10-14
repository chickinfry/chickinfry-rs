use std::collections::HashMap;
use std::time::Instant;

use chickinfry::client::conformance::Event;
use serde_json::{Value, json};

use crate::protocol::{Error, Result};

struct Call {
    started: Instant,
    deferred: bool,
    complete: bool,
    status: Option<u16>,
    read: usize,
    body: usize,
    library: usize,
    peak: usize,
    pending: Vec<&'static str>,
    events: Vec<Value>,
}

#[derive(Default)]
pub struct Log {
    sequence: u64,
    calls: HashMap<String, Call>,
}

impl Log {
    pub fn start(&mut self, id: &str, deferred: bool) {
        self.calls.entry(id.into()).or_insert_with(|| Call {
            started: Instant::now(),
            deferred,
            complete: true,
            status: None,
            read: 0,
            body: 0,
            library: 0,
            peak: 0,
            pending: Vec::new(),
            events: Vec::new(),
        });
    }

    fn push(sequence: &mut u64, call: &mut Call, id: &str, phase: &str) {
        *sequence += 1;
        call.peak = call.peak.max(call.body + call.library);
        call.events.push(json!({
            "sequence":*sequence, "callId":id, "elapsedMs":call.started.elapsed().as_millis(),
            "phase":phase, "httpStatus":call.status, "readBytes":call.read,
            "retainedBytes":if call.complete { Some(call.body + call.library) } else { None },
            "peakRetainedBytes":if call.complete { Some(call.peak) } else { None },
        }));
    }

    pub fn event(&mut self, id: &str, event: &Event) {
        let call = self.calls.get_mut(id).expect("registered call");
        match event {
            Event::Sending { .. } => {
                call.pending.clear();
                call.status = None;
                call.body = 0;
            }
            Event::Response { status } => call.status = Some(*status),
            Event::Transport {
                phase,
                bytes,
                retained,
            } => {
                if *phase == "headers" {
                    call.library = retained.unwrap_or(0);
                    call.complete &= retained.is_some();
                } else {
                    call.body = retained.unwrap_or(0);
                    call.complete &= retained.is_some();
                }
                call.read += bytes;
                call.peak = call.peak.max(call.body + call.library);
                if matches!(*phase, "read" | "limit") || !call.deferred {
                    Self::push(&mut self.sequence, call, id, phase);
                } else {
                    call.pending.push(phase);
                }
            }
            Event::TransportClosed => {
                call.library = 0;
                if call.pending.contains(&"cancel-requested")
                    || call
                        .events
                        .last()
                        .is_some_and(|event| event["phase"] == "cancel-requested")
                {
                    if call.deferred {
                        call.pending.push("cancel-observed");
                    } else {
                        Self::push(&mut self.sequence, call, id, "cancel-observed");
                    }
                }
            }
            _ => {}
        }
    }

    pub fn finish(&mut self, id: &str) {
        let call = self.calls.get_mut(id).expect("registered call");
        for phase in std::mem::take(&mut call.pending) {
            Self::push(&mut self.sequence, call, id, phase);
        }
        call.body = 0;
        Self::push(&mut self.sequence, call, id, "completed");
    }

    pub fn snapshot(&self, id: &str, after: u64) -> Result<Value> {
        let call = self
            .calls
            .get(id)
            .ok_or_else(|| Error::driver("invalid_reference"))?;
        if after > self.sequence {
            return Err(Error::driver("invalid_args"));
        }
        Ok(
            json!({"callId":id, "throughSequence":self.sequence, "complete":call.complete,
            "events":call.events.iter().filter(|event| event["sequence"].as_u64().unwrap() > after).collect::<Vec<_>>() }),
        )
    }
}
