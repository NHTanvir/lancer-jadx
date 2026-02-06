//! Cross-tool integration HTTP server (Lancer-standard).
//!
//! Every Lancer-clone GUI exposes a tiny local HTTP server on an
//! auto-allocated `127.0.0.1:<port>`, with the port written to
//! `%TEMP%/lancer-jadx.port` so the Lancer mothership can discover it.
//!
//! Endpoints:
//! * `GET  /v1/state`                    — current jobs / progress
//! * `POST /v1/import`                   — accept a target/file from another tool
//! * `GET  /v1/export?format=json|csv|sarif|markdown` — export the result set
//!
//! Hand-rolled HTTP/1.1 (std only) — no async runtime needed for the control
//! plane, so the GUI thread is never blocked.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// Shared state the HTTP server can read/serve. The GUI updates this.
#[derive(Default)]
pub struct SharedState {
    pub status: String,
    pub item_count: usize,
    pub current_input: Option<String>,
    pub export_json: String,
    /// Files imported from other Lancer tools (path strings).
    pub imported: Vec<String>,
}

pub type StateHandle = Arc<Mutex<SharedState>>;

/// Start the cross-tool server on an OS-allocated port; returns the bound port.
pub fn start(state: StateHandle) -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    write_port_file(port);

    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let state = state.clone();
            thread::spawn(move || {
                let _ = handle(stream, state);
            });
        }
    });
    Ok(port)
}

fn write_port_file(port: u16) {
    let dir = std::env::temp_dir();
    let path = dir.join("lancer-jadx.port");
    let _ = std::fs::write(path, port.to_string());
}

fn handle(stream: TcpStream, state: StateHandle) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    // Drain headers, capture content-length.
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }

    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };

    let mut stream = stream;
    match (method, path) {
        ("GET", "/v1/state") => {
            let s = state.lock().unwrap();
            let body = format!(
                "{{\"status\":{:?},\"items\":{},\"input\":{:?}}}",
                s.status,
                s.item_count,
                s.current_input.clone().unwrap_or_default()
            );
            respond(&mut stream, 200, "application/json", &body)
        }
        ("GET", "/v1/export") => {
            let fmt = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("format="))
                .unwrap_or("json");
            let s = state.lock().unwrap();
            let (ctype, body) = export(&s, fmt);
            respond(&mut stream, 200, ctype, &body)
        }
        ("POST", "/v1/import") => {
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body).ok();
            }
            let payload = String::from_utf8_lossy(&body).to_string();
            state.lock().unwrap().imported.push(payload);
            respond(&mut stream, 200, "application/json", "{\"ok\":true}")
        }
        _ => respond(&mut stream, 404, "text/plain", "not found"),
    }
}

fn export(s: &SharedState, fmt: &str) -> (&'static str, String) {
    match fmt {
        "csv" => (
            "text/csv",
            format!("status,items\n{},{}\n", s.status, s.item_count),
        ),
        "markdown" => (
            "text/markdown",
            format!("# lancer-jadx\n\n- status: {}\n- items: {}\n", s.status, s.item_count),
        ),
        "sarif" | "json" | _ => {
            if s.export_json.is_empty() {
                ("application/json", "{}".to_string())
            } else {
                ("application/json", s.export_json.clone())
            }
        }
    }
}

fn respond(stream: &mut TcpStream, code: u16, ctype: &str, body: &str) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()
}
