//! Focused transport checks for the shared client runtime: origin rules,
//! wire envelope, bounds, redirect rejection, and error preservation.

#[allow(
    dead_code,
    reason = "Each integration suite exercises a subset of the client module."
)]
#[path = "../src/client.rs"]
mod client;

#[allow(dead_code, reason = "The client only uses the RFC 3339 parser.")]
#[path = "../src/date_time.rs"]
mod date_time;

#[path = "../src/error_details.rs"]
mod error_details;

mod common;
#[path = "common/error.rs"]
mod error;

use client::{ClientError, HttpTransport, OperationError};
use common::{response, serve, serve_with};
use error::assert_safe_protocol;
use serde_json::json;

fn operation_error(error: ClientError) -> OperationError {
    error
        .operation_error
        .expect("expected remote operation error")
}

fn protocol_message(error: ClientError) -> String {
    assert!(error.operation_error.is_none());
    assert_safe_protocol(&error, &error.message);
    error.message
}

#[test]
fn rejects_unsupported_origins() {
    for origin in [
        "http://example.com",
        "ftp://example.com",
        "example.com",
        "https://user:secret@example.com",
        "https://example.com/service",
        "https://example.com/?a=b",
        "https://example.com/#anchor",
        "http://192.168.1.10:8080",
        "http://localhost:8080",
        "http://127.1",
        "http://0x7f000001",
        "http://0x7f.0.0.1",
        "http://0177.0.0.1",
        "http://2130706433",
        "http://127.00.0.1",
        "http://[::ffff:127.0.0.1]",
        "http://[0:0:0:0:0:0:0:1]",
        "http://[::01]",
        "http://%31%32%37.0.0.1",
        "https://example.com//",
        "https://example.com?",
        "https://example.com#",
        "https://example.com/?",
        "https://example.com/#",
        "http://127.0.0.1?",
        "http://[::1]#",
    ] {
        assert!(
            HttpTransport::new(origin, None).is_err(),
            "origin {origin} must be rejected"
        );
    }
}

#[test]
fn accepts_https_and_loopback_http_origins() {
    for origin in [
        "https://example.com",
        "http://127.0.0.1:8080",
        "http://127.254.0.1",
        "http://[::1]:9000",
        "https://example.com/",
        "http://127.0.0.1:8080/",
        "http://127.1.2.3",
        "http://127.255.255.255",
        "http://[::1]/",
    ] {
        assert!(
            HttpTransport::new(origin, None).is_ok(),
            "origin {origin} must be accepted"
        );
    }
}

#[test]
fn rejects_invalid_operation_names_without_sending() {
    let client = HttpTransport::new("https://example.com", None).expect("valid origin");
    for operation in [
        "",
        "Service.Method",
        "svc.method.extra",
        "svc.",
        ".method",
        "svc-method",
    ] {
        let message = protocol_message(client.invoke(operation, &json!({})).unwrap_err());
        assert_eq!(message, "invalid operation name", "operation {operation}");
    }
}

#[test]
fn rejects_oversized_requests() {
    let client = HttpTransport::new("https://example.com", None).expect("valid origin");
    let oversized = "a".repeat(4 << 20);
    let message = protocol_message(
        client
            .invoke("svc.op", &json!({ "text": oversized }))
            .unwrap_err(),
    );
    assert_eq!(
        message,
        "The request is too large. Reduce the submitted data and try again."
    );
}

#[test]
fn rejects_oversized_responses() {
    let (origin, receiver) = serve(&[response(
        "HTTP/1.1 200 OK",
        &format!("{{\"value\":\"{}\"}}", "a".repeat((1 << 20) + 16)),
    )]);
    let client = HttpTransport::new(&origin, Some(std::time::Duration::from_secs(10)))
        .expect("valid origin");
    let message = protocol_message(client.invoke("svc.op", &json!({})).unwrap_err());
    assert_eq!(
        message,
        "The response is too large. The operation may have completed; confirm its outcome before requesting less data."
    );
    let request = receiver.recv().expect("recorded request");
    assert_eq!(request.path, "/svc.op");
}

#[test]
fn transport_failures_discard_underlying_details() {
    let expected = "Could not complete the request. Check your connection and confirm the operation outcome before trying again.";
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let client = HttpTransport::new(&origin, None).unwrap();
    assert_safe_protocol(&client.invoke("svc.op", &json!({})).unwrap_err(), expected);

    let (release, held) = std::sync::mpsc::channel();
    let held = std::sync::Mutex::new(held);
    let (origin, requests) = serve_with(&[response("HTTP/1.1 200 OK", "{}")], move |_| {
        held.lock().unwrap().recv().unwrap();
    });
    let client = HttpTransport::new(&origin, Some(std::time::Duration::from_millis(100))).unwrap();
    let error = client.invoke("svc.op", &json!({})).unwrap_err();
    release.send(()).unwrap();
    assert_eq!(error.code, "deadline_exceeded");
    assert_eq!(error.status, None);
    assert!(error.outcome_unknown);
    assert_safe_protocol(&error, expected);
    assert_eq!(requests.recv().unwrap().path, "/svc.op");

    let (origin, requests) = serve(&["INVALID synthetic-transport-marker\r\n\r\n".into()]);
    let client = HttpTransport::new(&origin, None).unwrap();
    assert_safe_protocol(&client.invoke("svc.op", &json!({})).unwrap_err(), expected);
    assert_eq!(requests.recv().unwrap().path, "/svc.op");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("https://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().unwrap();
        let mut hello = [0; 1024];
        assert!(stream.read(&mut hello).unwrap() > 0);
        let _ = stream.write_all(b"synthetic-tls-marker");
    });
    let client = HttpTransport::new(&origin, Some(std::time::Duration::from_secs(2))).unwrap();
    assert_safe_protocol(&client.invoke("svc.op", &json!({})).unwrap_err(), expected);
    server.join().unwrap();
}

#[test]
fn truncated_response_discards_body_and_read_error() {
    let (origin, requests) = serve(&[response("HTTP/1.1 200 OK", "synthetic-body-marker")
        .replace("content-length: 21", "content-length: 100")]);
    let client = HttpTransport::new(&origin, None).unwrap();
    assert_safe_protocol(
        &client.invoke("svc.op", &json!({})).unwrap_err(),
        "Could not read the response. Confirm the operation outcome before trying again.",
    );
    assert_eq!(requests.recv().unwrap().path, "/svc.op");
}

#[test]
fn body_timeout_preserves_the_received_status() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (release, blocked) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
            .unwrap();
        blocked.recv().unwrap();
    });
    let client = HttpTransport::new(&origin, Some(std::time::Duration::from_millis(200))).unwrap();
    let error = client.invoke("svc.op", &json!({})).unwrap_err();
    release.send(()).unwrap();
    server.join().unwrap();
    assert_eq!(error.code, "deadline_exceeded");
    assert_eq!(error.status, Some(200));
    assert!(error.outcome_unknown);
    assert_safe_protocol(
        &error,
        "Could not read the response. Confirm the operation outcome before trying again.",
    );
}

#[test]
fn roundtrip_rejects_redirects_and_preserves_error_codes() {
    let (origin, receiver) = serve(&[
        response("HTTP/1.1 200 OK", "{\"ok\":true}"),
        response("HTTP/1.1 302 Found", "").replace(
            "content-length: 0",
            "content-length: 0\r\nlocation: https://elsewhere.example.com",
        ),
        response("HTTP/1.1 409 Conflict", "{\"error\":\"out_of_stock\"}"),
        response("HTTP/1.1 400 Bad Request", "{\"error\":\"Bad Code!\"}"),
        response("HTTP/1.1 500 Internal Server Error", "not json"),
    ]);
    let client = HttpTransport::new(&origin, Some(std::time::Duration::from_secs(10)))
        .expect("valid origin")
        .with_bearer(&"A".repeat(43))
        .expect("valid token");

    let value = client
        .invoke("catalog.find", &json!({ "id": "one" }))
        .expect("roundtrip");
    assert_eq!(value, json!({ "ok": true }));
    let request = receiver.recv().expect("recorded request");
    assert_eq!(request.path, "/catalog.find");
    assert_eq!(
        request.authorization.as_deref(),
        Some("Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    );
    assert!(request.body.contains("\"id\":\"one\""));

    let error = client.invoke("catalog.find", &json!({})).unwrap_err();
    assert_eq!((error.code.as_str(), error.status), ("internal", Some(302)));
    assert!(error.operation_error.is_none());
    assert!(error.outcome_unknown);
    let error = operation_error(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!((error.code.as_str(), error.status), ("out_of_stock", 409));
    for status in [400, 500] {
        let error = client.invoke("catalog.find", &json!({})).unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status),
            ("internal", Some(status))
        );
        assert!(error.operation_error.is_none());
        assert!(error.outcome_unknown);
    }
}

#[test]
fn operation_errors_preserve_only_valid_response_details() {
    let replies = [
        response(
            "HTTP/1.1 422 Unprocessable Entity",
            r#"{"error":"invalid_input","message":"","fields":[{"path":"items[4294967295].quantity","code":"required"}]}"#,
        ),
        response(
            "HTTP/1.1 422 Unprocessable Entity",
            r#"{"error":"invalid_input","message":"bad\nmessage","fields":[{"path":"quantity","code":"required"}]}"#,
        ),
        response(
            "HTTP/1.1 422 Unprocessable Entity",
            r#"{"error":"invalid_input","message":"safe","fields":[{"path":"quantity","code":"required"},{"path":"items[4294967296].quantity","code":"required"}]}"#,
        ),
        response(
            "HTTP/1.1 409 Conflict",
            r#"{"error":"conflict","message":null,"fields":[{"path":"quantity","code":"required"}]}"#,
        ),
    ];
    let (origin, _receiver) = serve(&replies);
    let client = HttpTransport::new(&origin, None).expect("valid origin");
    for (message, paths) in [
        (Some(""), &["items[4294967295].quantity"][..]),
        (None, &["quantity"][..]),
        (Some("safe"), &[][..]),
        (None, &[][..]),
    ] {
        let error = operation_error(client.invoke("probe.echo", &json!({})).unwrap_err());
        assert_eq!(error.response_message.as_deref(), message);
        let actual: Vec<_> = error
            .fields
            .iter()
            .map(|field| field.path.as_str())
            .collect();
        assert_eq!(actual, paths);
    }
}

#[test]
fn invalid_error_envelopes_preserve_http_status() {
    for body in [
        "not JSON",
        "{}",
        r#"{"message":"unavailable"}"#,
        r#"{"error":""}"#,
        r#"{"error":"Conflict"}"#,
        r#"{"error":"conflict1"}"#,
        r#"{"error":"bad-request"}"#,
        r#"{"error":42}"#,
        r#"{"error":null}"#,
        r#"{"error":{}}"#,
        r#"{"error":[]}"#,
    ] {
        let (origin, receiver) = serve(&[response("HTTP/1.1 503 Unavailable", body)]);
        let client = HttpTransport::new(&origin, None).expect("valid origin");
        let error = client.invoke("probe.echo", &json!({})).unwrap_err();
        assert_eq!((error.code.as_str(), error.status), ("internal", Some(503)));
        assert!(error.operation_error.is_none());
        assert!(error.outcome_unknown);
        assert_eq!(receiver.recv().expect("request").path, "/probe.echo");
    }
}

#[test]
fn encode_and_decode_enforce_declared_field_types() {
    #[derive(serde::Serialize)]
    struct Input {
        id: String,
    }
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct Output {
        id: String,
        count: i32,
    }
    let encoded = client::encode_input(&Input { id: "one".into() }).expect("encode");
    assert_eq!(encoded, json!({ "id": "one" }));

    let output: Output = client::decode_output(json!({ "id": "one", "count": 3 })).expect("decode");
    assert_eq!(
        output,
        Output {
            id: "one".into(),
            count: 3
        }
    );

    for broken in [
        json!({ "id": "one" }),
        json!({ "id": "one", "count": null }),
        json!({ "id": "one", "count": "3" }),
    ] {
        let error = client::decode_output::<Output>(broken).unwrap_err();
        assert_eq!(error.code, "internal");
        assert_eq!(error.status, None);
        assert!(error.outcome_unknown);
        let message = protocol_message(error);
        assert_eq!(message, "invalid operation response field");
    }
}
