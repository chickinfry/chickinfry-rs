use chickinfry::{
    client::{ClientError, Transport},
    realtime::{SubscribeOptions, create_realtime_client},
};
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Peer(Arc<AtomicUsize>);

impl Transport for Peer {
    fn invoke(&self, name: &str, input: &Value) -> Result<Value, ClientError> {
        assert_eq!(name, "realtime.ticket");
        assert_eq!(input, &serde_json::json!({}));
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(ClientError::new("unauthenticated", Some(401), false))
    }
}

#[test]
fn ticket_uses_the_existing_operation_transport() {
    let requests = Arc::new(AtomicUsize::new(0));
    let client = create_realtime_client(Arc::new(Peer(requests.clone())));
    let Err(invalid) = client.subscribe("invalid\nchannel", SubscribeOptions::default()) else {
        panic!("invalid channel accepted")
    };
    assert_eq!(invalid.code, "invalid_argument");
    assert_eq!(requests.load(Ordering::Relaxed), 0);
    let Err(remote) = client.subscribe("orders", SubscribeOptions::default()) else {
        panic!("denied ticket accepted")
    };
    assert_eq!(remote.code, "unauthenticated");
    assert_eq!(remote.status, Some(401));
    assert_eq!(requests.load(Ordering::Relaxed), 1);
}
