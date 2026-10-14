use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[path = "../../tests/common/mod.rs"]
mod common;

unsafe extern "C" {
    fn pipe(fds: *mut i32) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
}

struct Driver {
    child: Child,
    input: Option<ChildStdin>,
    output: mpsc::Receiver<Vec<u8>>,
    diagnostics: std::thread::JoinHandle<Vec<u8>>,
    observed: Vec<u8>,
}

impl Driver {
    fn start(secrets: &[u8]) -> Self {
        let mut fds = [0; 2];
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let mut write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        for fd in fds {
            assert_eq!(unsafe { fcntl(fd, 2, 1) }, 0);
        }
        let fd = read.as_raw_fd();
        let mut command = Command::new(env!("CARGO_BIN_EXE_chickinfry-conformance-driver"));
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if dup2(fd, 3) < 0 || fcntl(3, 2, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        write.write_all(secrets).unwrap();
        drop(write);
        drop(read);
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (sender, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).split(b'\n') {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let diagnostics = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut stderr, &mut bytes).unwrap();
            bytes
        });
        Self {
            child,
            input: Some(input),
            output,
            diagnostics,
            observed: Vec::new(),
        }
    }

    fn send(&mut self, value: Value) {
        writeln!(self.input.as_mut().unwrap(), "{value}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
    }
    fn next(&mut self) -> Value {
        let bytes = self
            .output
            .recv_timeout(Duration::from_secs(5))
            .expect("driver output deadline");
        self.observed.extend_from_slice(&bytes);
        serde_json::from_slice(&bytes).unwrap()
    }
    fn hello(&mut self) {
        self.send(json!({"id":"c:hello","command":"handshake","args":{"protocolVersions":[1],"runId":"run","requiredCapabilities":[],"target":{"language":"rust","role":"sdk","environment":"native"}}}));
        assert!(self.next()["error"].is_null());
    }
    fn request(&mut self, id: &str, command: &str, mut args: Value) {
        args["caseId"] = json!("diagnostic");
        args["timeoutMs"] = json!(5000);
        self.send(json!({"id":id,"command":command,"args":args}));
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn closed_credential_pipe_exits_with_fixed_error_without_exposing_values() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chickinfry-conformance-driver"));
    command
        .env(
            "CREDENTIAL_CANARY",
            "CANARY_PRIVATE_CREDENTIAL_1234567890abcdefghi",
        )
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            close(3);
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert_eq!(output.stderr, b"credential pipe unavailable\n");
}

#[test]
fn malformed_control_and_credential_pipes_never_expose_raw_values() {
    let secret = "CANARY_PRIVATE_CREDENTIAL_1234567890abcdefghi";
    let secrets = format!("{}\n", json!({"ref":"access","value":secret}));
    let mut driver = Driver::start(secrets.as_bytes());
    driver.hello();
    driver.request(
        "c:raw",
        "client.create",
        json!({"fixture":"plain","clientRef":"client","origin":secret,"bearerRef":"access","requestTimeoutMs":10}),
    );
    let response = driver.next();
    assert_eq!(response["error"]["kind"], "sdk");
    assert!(response["error"]["code"].is_null());
    writeln!(driver.input.as_mut().unwrap(), "{{\"{}\":", secret).unwrap();
    driver.input.as_mut().unwrap().flush().unwrap();
    assert!(!driver.child.wait().unwrap().success());
    let handle = std::mem::replace(&mut driver.diagnostics, std::thread::spawn(Vec::new));
    let stderr = String::from_utf8(handle.join().unwrap()).unwrap();
    assert!(!stderr.contains(secret));
    assert!(
        !String::from_utf8(driver.observed.clone())
            .unwrap()
            .contains(secret)
    );
    let mut duplicate = Driver::start(format!("{secrets}{secrets}").as_bytes());
    assert!(!duplicate.child.wait().unwrap().success());
    let handle = std::mem::replace(&mut duplicate.diagnostics, std::thread::spawn(Vec::new));
    assert!(
        !String::from_utf8(handle.join().unwrap())
            .unwrap()
            .contains(secret)
    );
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
fn record(origin: &str, access: &str, refresh: &str) -> String {
    format!(
        "{}\n",
        json!({"ref":"record", "value":json!({
        "origin":origin, "access_token":access, "refresh_token":refresh,
        "expires_at":"2099-01-01T00:00:00Z", "refresh_expires_at":"2099-01-08T00:00:00Z",
        "user_id":"user", "session_id":"session",
    }).to_string()})
    )
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[test]
fn auth_selector_calls_generated_methods_and_keeps_credentials_in_the_pipe() {
    let access = "J".repeat(43);
    let refresh = "K".repeat(43);
    let issued = json!({"access_token":access,"refresh_token":refresh,
        "expires_at":"2099-01-01T00:00:00Z","refresh_expires_at":"2099-01-08T00:00:00Z",
        "user_id":"user","session_id":"session"})
    .to_string();
    let mut replies = vec![common::response("HTTP/1.1 200 OK", &issued); 4];
    replies.push(common::response(
        "HTTP/1.1 200 OK",
        r#"{"id":"user","email":"hidden@example.invalid","session_id":"session"}"#,
    ));
    replies.push(common::response("HTTP/1.1 200 OK", r#"{"status":"ok"}"#));
    let (origin, requests) = common::serve(&replies);
    let secrets = [
        ("access", access.as_str()),
        ("refresh", refresh.as_str()),
        ("email", "hidden@example.invalid"),
        ("password", "private password canary"),
        ("credential", "private identity credential canary"),
    ]
    .into_iter()
    .map(|(reference, value)| format!("{}\n", json!({"ref":reference,"value":value})))
    .collect::<String>();
    let mut driver = Driver::start(secrets.as_bytes());
    driver.hello();
    for fixture in ["plain", "auth"] {
        driver.request(
            &format!("c:create-{fixture}"),
            "client.create",
            json!({"clientRef":fixture,"fixture":fixture,"origin":origin,"requestTimeoutMs":1000}),
        );
        assert!(driver.next()["error"].is_null());
    }
    driver.request("c:plain-auth", "client.call", json!({"clientRef":"plain","operation":"auth.refresh","input":{},"inputRefs":{"refresh_token":"refresh"}}));
    assert_eq!(driver.next()["error"]["kind"], "unimplemented");
    driver.request("c:conflict", "client.call", json!({"clientRef":"auth","operation":"auth.refresh","input":{"refresh_token":null},"inputRefs":{"refresh_token":"refresh"}}));
    assert_eq!(driver.next()["error"]["code"], "invalid_args");
    for (index, (operation, input, refs)) in [
        (
            "auth.signup",
            json!({}),
            json!({"email":"email","password":"password"}),
        ),
        (
            "auth.signin",
            json!({}),
            json!({"email":"email","password":"password"}),
        ),
        (
            "auth.identity",
            json!({"provider":"fixture"}),
            json!({"credential":"credential"}),
        ),
        (
            "auth.refresh",
            json!({}),
            json!({"refresh_token":"refresh"}),
        ),
        ("auth.session", json!({}), json!({})),
        ("auth.logout", json!({}), json!({})),
    ]
    .into_iter()
    .enumerate()
    {
        driver.request(
            &format!("c:auth-{index}"),
            "client.call",
            json!({"clientRef":"auth","operation":operation,"input":input,"inputRefs":refs}),
        );
        let response = driver.next();
        assert!(response["error"].is_null());
        if index < 4 {
            assert_eq!(
                response["result"]["credentialRefs"],
                json!({"access_token":"access","refresh_token":"refresh"})
            );
            assert!(response["result"]["output"].get("access_token").is_none());
            assert!(response["result"]["output"].get("refresh_token").is_none());
        }
        let actual = requests.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(actual.path, format!("/{operation}"));
        assert!(actual.authorization.is_none());
        let actual: Value = serde_json::from_str(&actual.body).unwrap();
        if index < 2 {
            assert!(actual["email"] == "hidden@example.invalid");
            assert!(actual["password"] == "private password canary");
        } else if index == 2 {
            assert!(actual["credential"] == "private identity credential canary");
        } else if index == 3 {
            assert!(actual["refresh_token"] == refresh);
        }
    }
    let output = String::from_utf8(driver.observed.clone()).unwrap();
    for secret in [
        access.as_str(),
        refresh.as_str(),
        "private password canary",
        "private identity credential canary",
    ] {
        assert!(!output.contains(secret));
    }
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[test]
fn session_overflow_limits_follow_the_first_excessive_read_in_each_exchange() {
    let large =
        json!({"wire_value":"x".repeat(1048577),"observed_at":"2099-01-01T00:00:00Z"}).to_string();
    let rejected = common::response("HTTP/1.1 401 Unauthorized", r#"{"error":"invalid_token"}"#);
    let access = "R".repeat(43);
    let refresh = "S".repeat(43);
    let issued = json!({"access_token":"T".repeat(43),"refresh_token":"U".repeat(43),
        "expires_at":"2099-01-01T00:00:00Z","refresh_expires_at":"2099-01-08T00:00:00Z",
        "user_id":"user","session_id":"session"})
    .to_string();
    for responses in [
        vec![common::response("HTTP/1.1 200 OK", &large)],
        vec![
            rejected.clone(),
            common::response("HTTP/1.1 200 OK", &large),
        ],
        vec![
            rejected.clone(),
            common::response("HTTP/1.1 200 OK", &issued),
            common::response("HTTP/1.1 200 OK", &large),
        ],
    ] {
        let exchanges = responses.len();
        let (origin, requests) = common::serve(&responses);
        let mut secrets = format!(
            "{}\n{}\n{}",
            json!({"ref":"access","value":access}),
            json!({"ref":"refresh","value":refresh}),
            record(&origin, &access, &refresh)
        );
        for (reference, value) in [
            ("nextAccess", "T".repeat(43)),
            ("nextRefresh", "U".repeat(43)),
        ] {
            secrets += &format!("{}\n", json!({"ref":reference,"value":value}));
        }
        let mut driver = Driver::start(secrets.as_bytes());
        driver.hello();
        driver.request("c:store", "session.store.create", json!({"storeRef":"store","origin":origin,"recordRef":"record","accessRef":"access","refreshRef":"refresh"}));
        assert!(driver.next()["error"].is_null());
        driver.request("c:create", "client.create", json!({"fixture":"auth","clientRef":"client","origin":origin,"storeRef":"store","requestTimeoutMs":1000}));
        assert!(driver.next()["error"].is_null());
        driver.request(
            "c:call",
            "client.call",
            json!({"clientRef":"client","operation":"probe.echo","input":{"wire_value":"ok"}}),
        );
        assert_eq!(driver.next()["error"]["kind"], "sdk");
        driver.request(
            "c:observe",
            "client.observe",
            json!({"callId":"c:call","afterSequence":0}),
        );
        let snapshot = driver.next()["result"].clone();
        assert_eq!(snapshot["complete"], true);
        let events = snapshot["events"].as_array().unwrap();
        let limit = events
            .iter()
            .position(|event| event["phase"] == "limit")
            .unwrap();
        assert_eq!(events[limit - 1]["phase"], "read");
        assert_eq!(events[limit]["readBytes"], events[limit - 1]["readBytes"]);
        assert!(events[limit - 1]["readBytes"].as_u64().unwrap() > 1048576);
        for _ in 0..exchanges {
            requests.recv_timeout(Duration::from_secs(1)).unwrap();
        }
    }
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[test]
fn diagnostic_two_actual_sdk_entries_and_store_reads_progress_while_first_call_is_held() {
    use std::net::TcpListener;
    let peer = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", peer.local_addr().unwrap());
    let access = "A".repeat(43);
    let refresh = "B".repeat(43);
    let secrets = format!(
        "{}\n{}\n{}",
        json!({"ref":"access","value":access}),
        json!({"ref":"refresh","value":refresh}),
        record(&origin, &access, &refresh)
    );
    let mut driver = Driver::start(secrets.as_bytes());
    driver.hello();
    driver.request(
        "c:store",
        "session.store.create",
        json!({"storeRef":"store","origin":origin,"recordRef":"record","accessRef":"access","refreshRef":"refresh"}),
    );
    assert!(driver.next()["error"].is_null());
    for (id, client) in [("c:create-first", "first"), ("c:create-second", "second")] {
        driver.request(
            id,
            "client.create",
            json!({"fixture":"plain","clientRef":client,"origin":origin,"storeRef":"store","requestTimeoutMs":1000}),
        );
        assert!(driver.next()["error"].is_null());
    }
    driver.request(
        "c:arm",
        "barrier.arm",
        json!({"barrierRef":"entered","point":"sdk-entered","participants":["c:first","c:second"]}),
    );
    assert!(driver.next()["error"].is_null());
    driver.request(
        "c:first",
        "client.call",
        json!({"clientRef":"first","operation":"probe.echo","input":{"wire_value":"ok"}}),
    );
    let first = driver.next();
    assert_eq!(first["command"], "barrier.arrive");
    assert_eq!(first["args"]["callId"], "c:first");
    assert_eq!(first["args"]["facts"], json!({"entered":true}));
    driver.request(
        "c:pending",
        "client.observe",
        json!({"callId":"c:first","afterSequence":0}),
    );
    let snapshot = driver.next();
    assert_eq!(snapshot["result"]["complete"], true);
    assert_eq!(snapshot["result"]["events"], json!([]));
    driver.request(
        "c:read",
        "session.store.read",
        json!({"storeRef":"store","includeTrace":true}),
    );
    assert_eq!(driver.next()["result"]["accessRef"], "access");
    driver.request(
        "c:second",
        "client.call",
        json!({"clientRef":"second","operation":"probe.echo","input":{"wire_value":"ok"}}),
    );
    let second = driver.next();
    assert_eq!(second["args"]["callId"], "c:second");
    let body =
        json!({"wire_value": access, "observed_at":"2026-01-02T03:04:05.123456Z"}).to_string();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = peer.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse::<usize>().unwrap();
                }
            }
            let mut input = vec![0; length];
            std::io::Read::read_exact(&mut reader, &mut input).unwrap();
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        }
    });
    for (sequence, arrival) in [(1, first), (2, second)] {
        driver.send(json!({"id":arrival["id"],"result":{"barrierRef":"entered","state":"released","sequence":sequence},"error":null}));
    }
    let first = driver.next();
    let second = driver.next();
    let ids = [
        first["id"].as_str().unwrap(),
        second["id"].as_str().unwrap(),
    ];
    assert!(ids.contains(&"c:first") && ids.contains(&"c:second"));
    for response in [first, second] {
        assert_eq!(response["result"]["httpStatus"], 200);
        assert!(response["result"]["output"].get("wire_value").is_none());
        assert_eq!(
            response["result"]["output"]["observed_at"],
            "2026-01-02T03:04:05.123456Z"
        );
    }
    let mut watermark = 0;
    for (index, call_id) in ["c:first", "c:second"].into_iter().enumerate() {
        driver.request(
            &format!("c:observe-{index}"),
            "client.observe",
            json!({"callId":call_id,"afterSequence":0}),
        );
        let snapshot = driver.next()["result"].clone();
        assert!(snapshot["throughSequence"].as_u64().unwrap() >= watermark);
        watermark = snapshot["throughSequence"].as_u64().unwrap();
        let events = snapshot["events"].as_array().unwrap();
        assert!(events.iter().any(|event| event["phase"] == "read"));
        assert_eq!(events.last().unwrap()["phase"], "completed");
        for event in events {
            assert_eq!(event.as_object().unwrap().len(), 8);
        }
        driver.request(
            &format!("c:watermark-{index}"),
            "client.observe",
            json!({"callId":call_id,"afterSequence":watermark}),
        );
        assert_eq!(driver.next()["result"]["events"], json!([]));
    }
    server.join().unwrap();
    assert!(
        !String::from_utf8(driver.observed.clone())
            .unwrap()
            .contains(&access)
    );
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[test]
fn diagnostic_unregistered_refresh_credentials_never_reach_stdout_or_stderr() {
    use std::net::TcpListener;
    let peer = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", peer.local_addr().unwrap());
    let access = "A".repeat(43);
    let refresh = "B".repeat(43);
    let new_access = "C".repeat(43);
    let new_refresh = "D".repeat(43);
    let rotated = json!({
        "access_token":new_access, "refresh_token":new_refresh,
        "expires_at":"2026-01-02T00:00:00Z", "refresh_expires_at":"2026-01-03T00:00:00Z",
        "user_id":"user", "session_id":"session",
    })
    .to_string();
    let server = std::thread::spawn(move || {
        for index in 0..6 {
            let (mut stream, _) = peer.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut headers = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
                headers.push_str(&line);
            }
            let mut bytes = vec![0; length];
            std::io::Read::read_exact(&mut reader, &mut bytes).unwrap();
            let input: Value = serde_json::from_slice(&bytes).unwrap();
            let (status, body) = match index {
                0 => (
                    "401 Unauthorized",
                    json!({"error":"invalid_token"}).to_string(),
                ),
                1 => {
                    assert!(headers.starts_with("POST /auth.refresh "));
                    assert!(input["refresh_token"] == "B".repeat(43));
                    ("200 OK", rotated.clone())
                }
                _ => {
                    assert!(headers.starts_with("POST /probe.echo "));
                    let bearer = if index == 5 { 'A' } else { 'C' }.to_string().repeat(43);
                    assert!(headers.to_ascii_lowercase().contains(&format!(
                        "authorization: bearer {}",
                        bearer.to_ascii_lowercase()
                    )));
                    ("200 OK", json!({"wire_value":input["wire_value"], "observed_at":"2026-01-02T03:04:05.123456Z"}).to_string())
                }
            };
            write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let secrets = format!(
        "{}\n{}\n{}",
        json!({"ref":"access","value":access}),
        json!({"ref":"refresh","value":refresh}),
        record(&origin, &access, &refresh)
    );
    let mut driver = Driver::start(secrets.as_bytes());
    driver.hello();
    driver.request(
        "c:store",
        "session.store.create",
        json!({"storeRef":"store","recordRef":"record","accessRef":"access","refreshRef":"refresh","origin":origin}),
    );
    assert!(driver.next()["error"].is_null());
    driver.request(
        "c:create",
        "client.create",
        json!({"fixture":"auth","clientRef":"client","origin":origin,"storeRef":"store","requestTimeoutMs":1000}),
    );
    assert!(driver.next()["error"].is_null());
    driver.request(
        "c:refresh",
        "client.call",
        json!({"clientRef":"client","operation":"probe.echo","input":{"wire_value":"ok"}}),
    );
    let response = driver.next();
    assert!(response["error"].is_null());
    assert_eq!(response["result"]["output"]["wire_value"], "ok");
    driver.request(
        "c:unregistered",
        "session.store.read",
        json!({"storeRef":"store","includeTrace":false}),
    );
    let response = driver.next();
    assert_eq!(response["error"]["kind"], "driver");
    assert_eq!(response["error"]["code"], "invalid_reference");
    for (index, value) in [&new_access, &new_refresh].into_iter().enumerate() {
        driver.request(&format!("c:echo-{index}"), "client.call", json!({"clientRef":"client","operation":"probe.echo","input":{"wire_value":format!("prefix-{value}-suffix")}}));
        let response = driver.next();
        assert!(response["error"].is_null());
        assert!(response["result"]["output"].get("wire_value").is_none());
    }
    driver.request(
        "c:replace",
        "session.store.write",
        json!({"storeRef":"store","accessRef":"access","refreshRef":"refresh","recordRef":"record"}),
    );
    assert_eq!(driver.next()["result"]["revision"], 4);
    driver.request(
        "c:registered",
        "session.store.read",
        json!({"storeRef":"store","includeTrace":false}),
    );
    assert_eq!(driver.next()["result"]["accessRef"], "access");
    driver.request("c:echo-replaced", "client.call", json!({"clientRef":"client","operation":"probe.echo","input":{"wire_value":format!("{new_access}:{new_refresh}")}}));
    let response = driver.next();
    assert!(response["error"].is_null());
    assert!(response["result"]["output"].get("wire_value").is_none());
    server.join().unwrap();
    drop(driver.input.take());
    assert!(driver.child.wait().unwrap().success());
    while let Ok(bytes) = driver.output.recv_timeout(Duration::from_secs(1)) {
        driver.observed.extend_from_slice(&bytes);
    }
    let handle = std::mem::replace(&mut driver.diagnostics, std::thread::spawn(Vec::new));
    let stderr = String::from_utf8(handle.join().unwrap()).unwrap();
    let stdout = String::from_utf8(driver.observed.clone()).unwrap();
    for secret in [&access, &refresh, &new_access, &new_refresh] {
        assert!(!stdout.contains(secret));
        assert!(!stderr.contains(secret));
    }
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[test]
fn diagnostic_sdk_errors_preserve_codes_status_and_transport_uncertainty() {
    use std::net::TcpListener;
    let peer = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", peer.local_addr().unwrap());
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let refused = format!("http://{}", unused.local_addr().unwrap());
    drop(unused);
    let server = std::thread::spawn(move || {
        for response in [
            Some(("409 Conflict", r#"{"error":"conflict"}"#)),
            Some(("200 OK", "{}")),
            None,
        ] {
            let (mut stream, _) = peer.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse::<usize>().unwrap();
                }
            }
            let mut bytes = vec![0; length];
            std::io::Read::read_exact(&mut reader, &mut bytes).unwrap();
            if let Some((status, body)) = response {
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        }
    });
    let mut driver = Driver::start(b"");
    driver.hello();
    for (name, origin) in [("client", origin), ("refused", refused)] {
        driver.request(
            &format!("c:create-{name}"),
            "client.create",
            json!({"fixture":"plain","clientRef":name,"origin":origin,"requestTimeoutMs":1000}),
        );
        assert!(driver.next()["error"].is_null());
    }
    for (id, client, code, status, unknown) in [
        ("conflict", "client", json!("conflict"), json!(409), false),
        (
            "corrupt",
            "client",
            json!("invalid_response"),
            json!(200),
            false,
        ),
        ("disconnected", "client", Value::Null, Value::Null, true),
        ("refused", "refused", Value::Null, Value::Null, false),
    ] {
        driver.request(
            &format!("c:{id}"),
            "client.call",
            json!({"clientRef":client,"operation":"probe.echo","input":{"wire_value":"ok"}}),
        );
        let response = driver.next();
        assert_eq!(
            response["error"],
            json!({"kind":"sdk","code":code,"httpStatus":status,"outcomeUnknown":unknown,"rawTransportDetails":false})
        );
        assert!(response["result"].is_null());
    }
    server.join().unwrap();
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[test]
fn diagnostic_eof_cancels_an_observed_entry_without_waiting_for_release() {
    let mut driver = Driver::start(b"");
    driver.hello();
    driver.request(
        "c:create",
        "client.create",
        json!({"fixture":"plain","clientRef":"client","origin":"http://127.0.0.1:9","requestTimeoutMs":1000}),
    );
    assert!(driver.next()["error"].is_null());
    driver.request(
        "c:arm",
        "barrier.arm",
        json!({"barrierRef":"entry","point":"sdk-entered","participants":["c:call"]}),
    );
    assert!(driver.next()["error"].is_null());
    driver.request(
        "c:call",
        "client.call",
        json!({"clientRef":"client","operation":"probe.echo","input":{"wire_value":"ok"}}),
    );
    assert_eq!(driver.next()["command"], "barrier.arrive");
    drop(driver.input.take());
    let response = driver.next();
    assert_eq!(response["id"], "c:call");
    assert_eq!(response["error"]["code"], "driver_failed");
    assert!(matches!(
        driver.output.recv_timeout(Duration::from_secs(1)),
        Err(mpsc::RecvTimeoutError::Disconnected)
    ));
    assert!(driver.child.wait().unwrap().success());
}

#[cfg(all(feature = "conformance", feature = "sdk"))]
#[test]
fn diagnostic_malformed_typed_inputs_are_invalid_args() {
    let mut driver = Driver::start(b"");
    driver.hello();
    driver.request(
        "c:create",
        "client.create",
        json!({"fixture":"plain","clientRef":"client","origin":"http://127.0.0.1:9","requestTimeoutMs":1000}),
    );
    assert!(driver.next()["error"].is_null());
    for (index, input) in [
        json!({}),
        json!({"wire_value":null}),
        json!({"wire_value":7}),
        json!({"wire_value":true}),
    ]
    .into_iter()
    .enumerate()
    {
        driver.request(
            &format!("c:input-{index}"),
            "client.call",
            json!({"clientRef":"client","operation":"probe.echo","input":input}),
        );
        let response = driver.next();
        assert_eq!(response["error"]["kind"], "driver");
        assert_eq!(response["error"]["code"], "invalid_args");
        assert!(response["error"]["httpStatus"].is_null());
    }
}
