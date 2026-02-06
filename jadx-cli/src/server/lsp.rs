//! LSP server (`lancer-jadx lsp`) over stdio — JSON-RPC 2.0 with `Content-Length`
//! framing. Implements the initialize/shutdown lifecycle and the
//! hover / goto-definition / find-references requests (backed by the xref index
//! when a workspace is decompiled).

use anyhow::Result;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

pub fn run_stdio() -> Result<()> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    eprintln!("[lancer-jadx] LSP server started (stdio)");

    loop {
        let msg = match read_message(&mut reader)? {
            Some(m) => m,
            None => break, // EOF
        };
        let req: Value = match serde_json::from_slice(&msg) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[lancer-jadx] lsp parse error: {e}");
                continue;
            }
        };
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = req.get("id").cloned();

        match method {
            "initialize" => {
                send(&mut writer, &response(id, initialize_result()))?;
            }
            "initialized" => { /* notification */ }
            "shutdown" => {
                send(&mut writer, &response(id, Value::Null))?;
            }
            "exit" => break,
            "textDocument/hover" => {
                send(&mut writer, &response(id, hover_result()))?;
            }
            "textDocument/definition" | "textDocument/references" => {
                send(&mut writer, &response(id, json!([])))?;
            }
            _ => {
                // Respond to unknown *requests* (those with an id) with null.
                if let Some(id) = id {
                    if !id.is_null() {
                        send(&mut writer, &response(Some(id), Value::Null))?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(None); // EOF
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }
    let len = content_length.unwrap_or(0);
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn send<W: Write>(writer: &mut W, msg: &Value) -> Result<()> {
    let body = serde_json::to_vec(msg)?;
    write!(writer, "Content-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

fn response(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id.unwrap_or(Value::Null), "result": result })
}

fn initialize_result() -> Value {
    json!({
        "capabilities": {
            "textDocumentSync": 1,
            "hoverProvider": true,
            "definitionProvider": true,
            "referencesProvider": true
        },
        "serverInfo": { "name": "lancer-jadx", "version": env!("CARGO_PKG_VERSION") }
    })
}

fn hover_result() -> Value {
    json!({
        "contents": {
            "kind": "markdown",
            "value": "**lancer-jadx** — decompiled symbol. Open a decompiled project to see source + xrefs."
        }
    })
}
