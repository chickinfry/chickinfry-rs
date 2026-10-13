//! Focused transport checks for the shared client runtime: origin rules,
//! wire envelope, bounds, redirect rejection, and error preservation.

#[path = "../src/client.rs"]
mod client;

mod common;

use client::{Client, ClientError, OperationError};
use common::{response, serve};
use serde_json::json;

fn operation_error(error: ClientError) -> OperationError {
    match error {
        ClientError::Operation(error) => error,
        other => panic!("expected operation error, got {other}"),
    }
}

fn protocol_message(error: ClientError) -> String {
    match error {
        ClientError::Protocol(message) => message,
        other => panic!("expected protocol error, got {other}"),
    }
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
            Client::new(origin).is_err(),
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
            Client::new(origin).is_ok(),
            "origin {origin} must be accepted"
        );
    }
}

#[test]
fn rejects_invalid_operation_names_without_sending() {
    let client = Client::new("https://example.com").expect("valid origin");
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
    let client = Client::new("https://example.com").expect("valid origin");
    let oversized = "a".repeat(4 << 20);
    let message = protocol_message(
        client
            .invoke("svc.op", &json!({ "text": oversized }))
            .unwrap_err(),
    );
    assert_eq!(message, "operation request is too large");
}

#[test]
fn rejects_oversized_responses() {
    let (origin, receiver) = serve(&[response(
        "HTTP/1.1 200 OK",
        &format!("{{\"value\":\"{}\"}}", "a".repeat((1 << 20) + 16)),
    )]);
    let client =
        Client::with_timeout(&origin, std::time::Duration::from_secs(10)).expect("valid origin");
    let message = protocol_message(client.invoke("svc.op", &json!({})).unwrap_err());
    assert_eq!(message, "operation response is too large");
    let request = receiver.recv().expect("recorded request");
    assert_eq!(request.path, "/svc.op");
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
    let client = Client::with_timeout(&origin, std::time::Duration::from_secs(10))
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

    let error = operation_error(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!(
        (error.code.as_str(), error.status),
        ("redirect_not_allowed", 302)
    );

    let error = operation_error(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!((error.code.as_str(), error.status), ("out_of_stock", 409));

    let error = operation_error(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!(
        (error.code.as_str(), error.status),
        ("invalid_response", 400)
    );

    let error = operation_error(client.invoke("catalog.find", &json!({})).unwrap_err());
    assert_eq!(
        (error.code.as_str(), error.status),
        ("invalid_response", 500)
    );
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
        let client = Client::new(&origin).expect("valid origin");
        let error = operation_error(client.invoke("probe.echo", &json!({})).unwrap_err());
        assert_eq!(
            (error.code.as_str(), error.status),
            ("invalid_response", 503)
        );
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
        let message = protocol_message(client::decode_output::<Output>(broken).unwrap_err());
        assert_eq!(message, "invalid operation response field");
    }
}
