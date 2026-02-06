//! LSP server (`lancer-jadx lsp`) over stdio — JSON-RPC 2.0 with `Content-Length`
//! framing. Implements the initialize/shutdown lifecycle and the
//! hover / goto-definition / find-references requests (backed by the xref index
//! when a workspace is decompiled).

use anyhow::Result;
use jadx_core::XrefIndex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

/// In-memory workspace the LSP serves: decompiled sources keyed by document URI
/// (or path) plus an optional cross-reference index. Either may be empty, in
/// which case requests degrade gracefully to `null`/empty results.
#[derive(Debug, Default, Clone)]
pub struct LspWorkspace {
    /// document path/URI → full decompiled source text.
    pub sources: BTreeMap<String, String>,
    /// cross-reference index for definition/references lookups.
    pub xref: Option<XrefIndex>,
}

impl LspWorkspace {
    pub fn new() -> Self {
        LspWorkspace::default()
    }

    /// Attach (or replace) a decompiled source document.
    pub fn add_source(&mut self, path: impl Into<String>, source: impl Into<String>) {
        self.sources.insert(path.into(), source.into());
    }

    /// Attach a cross-reference index.
    pub fn set_xref(&mut self, xref: XrefIndex) {
        self.xref = Some(xref);
    }

    fn has_workspace(&self) -> bool {
        !self.sources.is_empty() || self.xref.is_some()
    }

    /// Look up a source document by its URI, tolerating `file://` prefixes and
    /// path separator differences.
    fn source_for_uri(&self, uri: &str) -> Option<(&String, &String)> {
        if let Some((k, v)) = self.sources.get_key_value(uri) {
            return Some((k, v));
        }
        let normalized = normalize_uri(uri);
        self.sources
            .iter()
            .find(|(k, _)| normalize_uri(k) == normalized)
    }
}

/// Run the LSP server on stdio with an empty workspace.
pub fn run_stdio() -> Result<()> {
    run_stdio_with(LspWorkspace::new())
}

/// Run the LSP server on stdio backed by the given workspace.
pub fn run_stdio_with(workspace: LspWorkspace) -> Result<()> {
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
        let params = req.get("params").cloned().unwrap_or(Value::Null);

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
                send(&mut writer, &response(id, workspace.hover(&params)))?;
            }
            "textDocument/definition" => {
                send(&mut writer, &response(id, workspace.definition(&params)))?;
            }
            "textDocument/references" => {
                send(&mut writer, &response(id, workspace.references(&params)))?;
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

impl LspWorkspace {
    /// `textDocument/hover` → the decompiled source line/snippet at the cursor,
    /// or a symbol summary, rendered as markdown. Returns `null` when there is
    /// nothing useful to show.
    fn hover(&self, params: &Value) -> Value {
        if !self.has_workspace() {
            return Value::Null;
        }
        let (uri, line, character) = match position(params) {
            Some(p) => p,
            None => return Value::Null,
        };
        let Some((_, source)) = self.source_for_uri(&uri) else {
            return Value::Null;
        };
        let Some(text) = source.lines().nth(line) else {
            return Value::Null;
        };
        let symbol = word_at(text, character);

        let mut value = String::new();
        value.push_str("```");
        value.push_str(lang_for_uri(&uri));
        value.push('\n');
        value.push_str(text.trim_end());
        value.push_str("\n```");

        if let Some(sym) = symbol.as_deref() {
            if let Some(summary) = self.symbol_summary(sym) {
                value.push_str("\n\n");
                value.push_str(&summary);
            }
        }

        json!({
            "contents": { "kind": "markdown", "value": value }
        })
    }

    /// A one-line markdown summary of what the xref index knows about `sym`.
    fn symbol_summary(&self, sym: &str) -> Option<String> {
        let xref = self.xref.as_ref()?;
        let mut parts = Vec::new();
        let callers: usize = xref
            .method_callers
            .iter()
            .filter(|(k, _)| matches_symbol(k, sym))
            .map(|(_, v)| v.len())
            .sum();
        if callers > 0 {
            parts.push(format!("{callers} caller(s)"));
        }
        let subs = xref.subclasses_of(sym).len();
        if subs > 0 {
            parts.push(format!("{subs} subclass(es)"));
        }
        let impls = xref.implementors_of(sym).len();
        if impls > 0 {
            parts.push(format!("{impls} implementor(s)"));
        }
        if parts.is_empty() {
            None
        } else {
            Some(format!("**`{sym}`** — {}", parts.join(", ")))
        }
    }

    /// `textDocument/definition` → definition site(s) for the symbol under the
    /// cursor, resolved through the xref index (subclasses/implementors point at
    /// the base type; method callers point back at the callee).
    fn definition(&self, params: &Value) -> Value {
        let Some(xref) = self.xref.as_ref() else {
            return json!([]);
        };
        let Some((uri, line, character)) = position(params) else {
            return json!([]);
        };
        let Some(sym) = self.symbol_at(&uri, line, character) else {
            return json!([]);
        };

        // A definition is a single declaration: prefer the callee/type itself.
        // Surface any related declarations we can name through the index.
        let mut targets: Vec<String> = Vec::new();
        for key in xref.method_callers.keys() {
            if matches_symbol(key, &sym) {
                targets.push(key.clone());
            }
        }
        // Field declarations.
        for key in xref.field_readers.keys().chain(xref.field_writers.keys()) {
            if matches_symbol(key, &sym) {
                targets.push(key.clone());
            }
        }
        targets.sort();
        targets.dedup();

        let locations: Vec<Value> = targets.iter().map(|t| symbol_location(t)).collect();
        Value::Array(locations)
    }

    /// `textDocument/references` → all use sites of the symbol under the cursor:
    /// method callers, field readers/writers, subclasses and implementors.
    fn references(&self, params: &Value) -> Value {
        let Some(xref) = self.xref.as_ref() else {
            return json!([]);
        };
        let Some((uri, line, character)) = position(params) else {
            return json!([]);
        };
        let Some(sym) = self.symbol_at(&uri, line, character) else {
            return json!([]);
        };

        let mut refs: Vec<String> = Vec::new();
        for (key, callers) in &xref.method_callers {
            if matches_symbol(key, &sym) {
                refs.extend(callers.iter().cloned());
            }
        }
        for (key, readers) in &xref.field_readers {
            if matches_symbol(key, &sym) {
                refs.extend(readers.iter().cloned());
            }
        }
        for (key, writers) in &xref.field_writers {
            if matches_symbol(key, &sym) {
                refs.extend(writers.iter().cloned());
            }
        }
        refs.extend(xref.subclasses_of(&sym).iter().cloned());
        refs.extend(xref.implementors_of(&sym).iter().cloned());
        refs.sort();
        refs.dedup();

        let locations: Vec<Value> = refs.iter().map(|r| symbol_location(r)).collect();
        Value::Array(locations)
    }

    /// Resolve the identifier under a cursor position into a symbol string.
    fn symbol_at(&self, uri: &str, line: usize, character: usize) -> Option<String> {
        let (_, source) = self.source_for_uri(uri)?;
        let text = source.lines().nth(line)?;
        word_at(text, character)
    }
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

/// Extract `(uri, line, character)` from request params (LSP TextDocumentPositionParams).
fn position(params: &Value) -> Option<(String, usize, usize)> {
    let uri = params
        .get("textDocument")
        .and_then(|d| d.get("uri"))
        .and_then(|u| u.as_str())?
        .to_string();
    let pos = params.get("position");
    let line = pos
        .and_then(|p| p.get("line"))
        .and_then(|l| l.as_u64())
        .unwrap_or(0) as usize;
    let character = pos
        .and_then(|p| p.get("character"))
        .and_then(|c| c.as_u64())
        .unwrap_or(0) as usize;
    Some((uri, line, character))
}

/// The identifier word at `character` within `line` (`.` and `$` are part of
/// qualified names but split out the simple identifier under the cursor).
fn word_at(line: &str, character: usize) -> Option<String> {
    let chars: Vec<char> = line.chars().collect();
    if chars.is_empty() {
        return None;
    }
    let mut idx = character.min(chars.len().saturating_sub(1));
    let is_ident = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    if !is_ident(chars[idx]) {
        // Try the character just before the cursor.
        if idx == 0 || !is_ident(chars[idx - 1]) {
            return None;
        }
        idx -= 1;
    }
    let mut start = idx;
    while start > 0 && is_ident(chars[start - 1]) {
        start -= 1;
    }
    let mut end = idx;
    while end + 1 < chars.len() && is_ident(chars[end + 1]) {
        end += 1;
    }
    let word: String = chars[start..=end].iter().collect();
    if word.is_empty() {
        None
    } else {
        Some(word)
    }
}

/// Whether an xref key (`Class->member` or a class name) refers to `sym`.
fn matches_symbol(key: &str, sym: &str) -> bool {
    if key == sym {
        return true;
    }
    if let Some((class, member)) = key.split_once("->") {
        member == sym || class == sym || simple(class) == sym || simple(member) == sym
    } else {
        simple(key) == sym
    }
}

/// Strip package / descriptor decoration to the trailing simple name.
fn simple(name: &str) -> &str {
    let trimmed = name.trim_end_matches(';');
    trimmed
        .rsplit(|c| c == '.' || c == '/' || c == '$')
        .next()
        .unwrap_or(trimmed)
}

/// Build an LSP `Location` for a symbol string. We do not have on-disk line
/// positions for xref targets, so we synthesize a stable zero-range location
/// whose URI encodes the symbol — clients can still navigate / display it.
fn symbol_location(symbol: &str) -> Value {
    json!({
        "uri": format!("jadx-symbol:{symbol}"),
        "range": {
            "start": { "line": 0, "character": 0 },
            "end": { "line": 0, "character": 0 }
        }
    })
}

/// Strip a `file://` scheme and normalize path separators for comparison.
fn normalize_uri(uri: &str) -> String {
    let path = uri.strip_prefix("file://").unwrap_or(uri);
    path.replace('\\', "/")
}

/// A markdown/code-fence language hint based on the document extension.
fn lang_for_uri(uri: &str) -> &'static str {
    if uri.ends_with(".kt") {
        "kotlin"
    } else {
        "java"
    }
}
