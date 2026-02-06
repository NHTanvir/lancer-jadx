//! MCP server (`lancer-jadx serve --port`) — a newline-delimited JSON-RPC 2.0
//! endpoint exposing the decompiler as tools for Claude / Cursor.
//!
//! Tools: `decompile_apk`, `extract_strings`, `extract_manifest`,
//! `find_pattern`, `tree`, `findings`.

use anyhow::Result;
use jadx_core::{Jadx, JadxArgs};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

pub fn serve(port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr)?;
    eprintln!("[lancer-jadx] MCP server listening on {addr}");
    eprintln!("[lancer-jadx] newline-delimited JSON-RPC 2.0; methods: initialize, tools/list, tools/call");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle_connection(s) {
                    eprintln!("[lancer-jadx] connection error: {e}");
                }
            }
            Err(e) => eprintln!("[lancer-jadx] accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_connection(stream: TcpStream) -> Result<()> {
    let mut writer = stream.try_clone()?;
    let reader = BufReader::new(stream);
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle_request(&req),
            Err(e) => error_response(&Value::Null, -32700, &format!("parse error: {e}")),
        };
        let mut text = serde_json::to_string(&response)?;
        text.push('\n');
        writer.write_all(text.as_bytes())?;
        writer.flush()?;
    }
    Ok(())
}

fn handle_request(req: &Value) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    match method {
        "initialize" => ok_response(
            &id,
            json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": { "name": "lancer-jadx", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": { "tools": {} }
            }),
        ),
        "tools/list" => ok_response(&id, json!({ "tools": tool_list() })),
        "tools/call" => match call_tool(req.get("params").unwrap_or(&Value::Null)) {
            Ok(text) => ok_response(
                &id,
                json!({ "content": [ { "type": "text", "text": text } ] }),
            ),
            Err(e) => error_response(&id, -32000, &e.to_string()),
        },
        "ping" => ok_response(&id, json!({})),
        _ => error_response(&id, -32601, &format!("method not found: {method}")),
    }
}

fn tool_list() -> Value {
    let apk_schema = json!({
        "type": "object",
        "properties": { "apk": { "type": "string", "description": "path to APK/DEX/AAR/JAR" } },
        "required": ["apk"]
    });
    json!([
        { "name": "decompile_apk", "description": "Decompile and return a JSON package tree", "inputSchema": apk_schema },
        { "name": "extract_strings", "description": "Extract string resources + DEX strings as JSON", "inputSchema": apk_schema },
        { "name": "extract_manifest", "description": "Decode AndroidManifest.xml", "inputSchema": apk_schema },
        {
            "name": "find_pattern",
            "description": "Regex-search decompiled source",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "apk": { "type": "string" },
                    "pattern": { "type": "string" }
                },
                "required": ["apk", "pattern"]
            }
        },
        { "name": "tree", "description": "Emit the JSON package tree", "inputSchema": apk_schema },
        { "name": "findings", "description": "Run the security findings scan (JSON)", "inputSchema": apk_schema }
    ])
}

fn call_tool(params: &Value) -> Result<String> {
    let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let args = params.get("arguments").cloned().unwrap_or(Value::Null);
    let apk = args
        .get("apk")
        .and_then(|a| a.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'apk' argument"))?;

    let jadx = load(apk)?;
    match name {
        "decompile_apk" | "tree" => Ok(jadx.tree_json()),
        "extract_strings" => Ok(jadx.extract_strings_json()),
        "extract_manifest" => Ok(jadx
            .manifest_xml()
            .unwrap_or_else(|| "<!-- no manifest -->".to_string())),
        "find_pattern" => {
            let pattern = args
                .get("pattern")
                .and_then(|p| p.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing 'pattern' argument"))?;
            let hits = jadx.find_pattern(pattern)?;
            let lines: Vec<String> = hits
                .iter()
                .map(|(f, l, t)| format!("{f}:{l}: {t}"))
                .collect();
            Ok(lines.join("\n"))
        }
        "findings" => {
            let findings = jadx.run_findings();
            Ok(jadx_core::report::findings_json(&findings))
        }
        other => Err(anyhow::anyhow!("unknown tool: {other}")),
    }
}

fn load(apk: &str) -> Result<Jadx> {
    let mut args = JadxArgs::default();
    args.inputs = vec![PathBuf::from(apk)];
    Jadx::load(args)
}

fn ok_response(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
