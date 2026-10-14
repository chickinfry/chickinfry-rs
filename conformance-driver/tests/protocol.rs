use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

use chickinfry_conformance_driver::{protocol, run};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Output(Arc<Mutex<Vec<u8>>>);
impl Write for Output {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn handshake() -> Value {
    json!({"id":"c:hello","command":"handshake","args":{"protocolVersions":[1],"runId":"run","requiredCapabilities":[],"target":{"language":"rust","role":"sdk","environment":"native"}}})
}
fn command(id: &str, command: &str, mut args: Value) -> Value {
    args["caseId"] = json!("diagnostic");
    args["timeoutMs"] = json!(1000);
    json!({"id":id,"command":command,"args":args})
}
fn execute(messages: &[Value], secrets: &[u8]) -> (protocol::Result<()>, Vec<Value>, Vec<u8>) {
    let output = Output::default();
    let data = messages
        .iter()
        .map(|v| format!("{v}\n"))
        .collect::<String>();
    let outcome = run(Cursor::new(data), output.clone(), &mut Cursor::new(secrets));
    let bytes = output.0.lock().unwrap().clone();
    let lines = bytes
        .split(|v| *v == b'\n')
        .filter(|v| !v.is_empty())
        .map(|v| serde_json::from_slice(v).unwrap())
        .collect();
    (outcome, lines, bytes)
}

#[test]
fn strict_json_envelopes_reject_duplicates_unknown_fields_and_bad_response_shapes() {
    for line in [
        r#"{"id":"c:x","id":"c:y","command":"handshake","args":{}}"#,
        r#"{"id":"c:x","command":"client.call","args":{"input":{"key":1,"key":2}}}"#,
        r#"{"id":"c:x","command":"handshake","args":{},"expect":{}}"#,
        r#"{"id":"d:x","command":"handshake","args":{}}"#,
        r#"{"id":"d:x","result":{},"error":{}}"#,
        r#"{"id":"d:x","result":null,"error":null}"#,
        r#"{"id":"d:x","result":{}}"#,
        r#"{"id":"d:x","result":[],"error":null}"#,
    ] {
        assert_eq!(
            protocol::message(line.as_bytes())
                .err()
                .unwrap()
                .code
                .as_deref(),
            Some("protocol_violation")
        );
    }
    assert!(protocol::message(br#"{"id":"d:one","result":{},"error":null}"#).is_ok());
    assert!(protocol::name(&format!("a/{}", "x".repeat(254))));
    assert!(!protocol::name(&"x".repeat(257)));
    assert!(!protocol::name("/leading-slash"));
}

#[test]
fn bounded_lines_count_utf8_bytes_and_reject_truncation() {
    assert!(protocol::line(&mut Cursor::new(b"{}".as_slice())).is_err());
    let mut allowed = vec![b'x'; protocol::MAX_LINE];
    allowed.push(b'\n');
    assert_eq!(
        protocol::line(&mut Cursor::new(allowed))
            .unwrap()
            .unwrap()
            .len(),
        protocol::MAX_LINE
    );
    assert!(protocol::line(&mut Cursor::new(vec![b'x'; protocol::MAX_LINE + 1])).is_err());
    assert!(protocol::json("🎉".repeat(protocol::MAX_LINE / 4 + 1).as_bytes()).is_err());
}

#[test]
fn handshake_negotiates_and_rejects_versions_missing_capabilities_and_early_commands() {
    let (outcome, responses, _) = execute(&[handshake()], b"");
    assert!(outcome.is_ok());
    assert_eq!(responses[0]["result"]["protocolVersion"], 1);
    assert!(responses[0]["error"].is_null());
    for (key, value, code) in [
        ("protocolVersions", json!([9]), "protocol_mismatch"),
        (
            "target",
            json!({"language":"go","role":"sdk","environment":"native"}),
            "unimplemented",
        ),
        (
            "requiredCapabilities",
            json!(["imaginary"]),
            "unimplemented",
        ),
    ] {
        let mut hello = handshake();
        hello["args"][key] = value;
        let (outcome, responses, _) = execute(&[hello], b"");
        assert_eq!(outcome.unwrap_err().code.as_deref(), Some(code));
        assert_eq!(responses[0]["error"]["code"], code);
    }
    let early = command(
        "c:early",
        "session.store.read",
        json!({"storeRef":"store","includeTrace":false}),
    );
    assert!(execute(&[early], b"").0.is_err());
}

#[test]
fn credential_bootstrap_limits_include_lf_and_fail_before_handshake() {
    let lines: Vec<_> = (0..16)
        .map(|index| {
            let mut line = json!({"ref":format!("credential-{index}"),"value":""}).to_string();
            let padding = (64 << 10) - line.len() - 1;
            line = json!({"ref":format!("credential-{index}"),"value":"Z".repeat(padding)})
                .to_string();
            line.push('\n');
            assert_eq!(line.len(), 64 << 10);
            line
        })
        .collect();
    let at_limit = lines.concat();
    assert_eq!(at_limit.len(), 1 << 20);
    assert!(execute(&[handshake()], at_limit.as_bytes()).0.is_ok());
    for rejected in [
        lines[0].replacen("ZZ", "ZZZ", 1),
        format!("{at_limit}{}\n", json!({"ref":"overflow","value":"other"})),
        lines[0].trim_end_matches('\n').to_string(),
    ] {
        let (outcome, responses, _) = execute(&[handshake()], rejected.as_bytes());
        assert_eq!(
            outcome.unwrap_err().code.as_deref(),
            Some("protocol_violation")
        );
        assert!(responses.is_empty());
    }
}

#[test]
fn run_ids_unknown_fields_and_unregistered_responses_are_violations() {
    assert_eq!(
        execute(&[handshake(), handshake()], b"")
            .0
            .unwrap_err()
            .code
            .as_deref(),
        Some("protocol_violation")
    );
    let mut request = command(
        "c:store",
        "session.store.create",
        json!({"storeRef":"store"}),
    );
    request["args"]["expect"] = json!({});
    assert_eq!(
        execute(&[handshake(), request], b"")
            .0
            .unwrap_err()
            .code
            .as_deref(),
        Some("protocol_violation")
    );
    assert!(
        execute(
            &[
                handshake(),
                json!({"id":"d:unknown","result":{},"error":null})
            ],
            b""
        )
        .0
        .is_err()
    );
}

#[test]
fn credentials_are_pipe_only_and_stores_expose_references_and_revisions() {
    let access = "A".repeat(43);
    let refresh = "B".repeat(43);
    let secrets = format!(
        "{}\n{}\n",
        json!({"ref":"access","value":access}),
        json!({"ref":"refresh","value":refresh})
    );
    let (outcome, responses, bytes) = execute(
        &[
            handshake(),
            command(
                "c:create",
                "session.store.create",
                json!({"storeRef":"store","accessRef":"access","refreshRef":"refresh"}),
            ),
            command(
                "c:read",
                "session.store.read",
                json!({"storeRef":"store","includeTrace":false}),
            ),
            command(
                "c:write",
                "session.store.write",
                json!({"storeRef":"store","accessRef":"refresh","refreshRef":"access"}),
            ),
            command(
                "c:read-again",
                "session.store.read",
                json!({"storeRef":"store","includeTrace":false}),
            ),
        ],
        secrets.as_bytes(),
    );
    assert!(outcome.is_ok());
    assert_eq!(responses[2]["result"]["accessRef"], "access");
    assert_eq!(responses[4]["result"]["revision"], 2);
    assert_eq!(responses[4]["result"]["accessRef"], "refresh");
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains(&access) && !text.contains(&refresh));
    assert!(
        execute(&[handshake()], format!("{secrets}{secrets}").as_bytes())
            .0
            .is_err()
    );
}

#[test]
fn unavailable_operations_are_not_success_or_advertised_support() {
    let (_, responses, _) = execute(
        &[
            handshake(),
            command(
                "c:create",
                "client.create",
                json!({"clientRef":"client","origin":"http://127.0.0.1:9","requestTimeoutMs":10}),
            ),
            command(
                "c:list",
                "client.call",
                json!({"clientRef":"client","operation":"probe.list","input":{}}),
            ),
            command("c:unknown", "peer.start", json!({})),
        ],
        b"",
    );
    for id in ["c:list", "c:unknown"] {
        let response = responses.iter().find(|v| v["id"] == id).unwrap();
        assert_eq!(response["error"]["kind"], "unimplemented");
        assert!(response["result"].is_null());
    }
}

#[test]
fn auth_fixture_cases_are_explicitly_unimplemented_without_fixture_selection() {
    for case_id in ["C-08", "C-09", "C-10"] {
        let mut create = command(
            "c:auth",
            "client.create",
            json!({"clientRef":"auth","origin":"http://127.0.0.1:9","requestTimeoutMs":10}),
        );
        create["args"]["caseId"] = json!(case_id);
        let (outcome, responses, _) = execute(&[handshake(), create], b"");
        assert!(outcome.is_ok());
        assert_eq!(responses[1]["error"]["kind"], "unimplemented");
        assert!(responses[1]["result"].is_null());
    }
}

#[cfg(not(all(feature = "sdk", feature = "conformance")))]
#[test]
fn build_without_sdk_observation_has_no_barrier_or_session_trace() {
    let (outcome, responses, _) = execute(
        &[
            handshake(),
            command(
                "c:trace",
                "session.store.read",
                json!({"storeRef":"missing","includeTrace":true}),
            ),
            command(
                "c:barrier",
                "barrier.arm",
                json!({"barrierRef":"entered","point":"sdk-entered","participants":["c:call"]}),
            ),
        ],
        b"",
    );
    assert!(outcome.is_ok());
    let caps = responses[0]["result"]["capabilities"].as_array().unwrap();
    assert!(
        !caps.contains(&json!("session.trace"))
            && !caps.contains(&json!("barrier"))
            && !caps.contains(&json!("client.call"))
    );
    for response in &responses[1..] {
        assert_eq!(response["error"]["code"], "unimplemented");
    }
}
