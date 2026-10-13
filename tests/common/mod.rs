//! Minimal loopback HTTP server used by the shared client checks.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::thread;

/// One recorded client request.
#[derive(Debug)]
pub struct Request {
    pub path: String,
    pub authorization: Option<String>,
    pub body: String,
}

/// Starts a loopback server that answers the next `responses.len()`
/// connections in order and records every request it receives.
pub fn serve(responses: &[String]) -> (String, Receiver<Request>) {
    serve_with(responses, |_| {})
}

/// Allows a test to hold a response at an observed request, without timing races.
pub fn serve_with(
    responses: &[String],
    before_response: impl Fn(usize) + Send + Sync + 'static,
) -> (String, Receiver<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let origin = format!("http://{}", listener.local_addr().expect("local address"));
    let (sender, receiver) = channel();
    let scripted: Vec<String> = responses.to_vec();
    let before_response = Arc::new(before_response);
    thread::spawn(move || {
        for (index, response) in scripted.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let sender = sender.clone();
            let before_response = before_response.clone();
            thread::spawn(move || {
                let request = read_request(&mut stream);
                sender.send(request).expect("record request");
                before_response(index);
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            });
        }
    });
    (origin, receiver)
}

/// Builds one scripted HTTP/1.1 response; the connection closes after it so
/// every request is a separate recorded connection.
pub fn response(status_line: &str, body: &str) -> String {
    format!(
        "{}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        status_line,
        body.len(),
        body
    )
}

fn read_request(stream: &mut TcpStream) -> Request {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end = loop {
        if let Some(position) = find(&buffer, b"\r\n\r\n") {
            break position;
        }
        let read = stream.read(&mut chunk).expect("read request head");
        assert!(read > 0, "connection closed before request head ended");
        buffer.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8(buffer[..header_end].to_vec()).expect("request head utf8");
    let mut lines = head.split("\r\n");
    let request_line = lines.next().expect("request line");
    let mut parts = request_line.split(' ');
    let _method = parts.next().expect("method");
    let path = parts.next().expect("path").to_owned();
    let mut authorization = None;
    let mut content_length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().expect("content-length");
        }
    }
    let body_start = header_end + 4;
    while buffer.len() < body_start + content_length {
        let read = stream.read(&mut chunk).expect("read request body");
        assert!(read > 0, "connection closed before request body ended");
        buffer.extend_from_slice(&chunk[..read]);
    }
    let body = String::from_utf8(buffer[body_start..body_start + content_length].to_vec())
        .expect("request body utf8");
    Request {
        path,
        authorization,
        body,
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
