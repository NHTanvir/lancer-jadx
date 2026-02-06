//! Protocol servers: LSP (stdio) and MCP (TCP), both hand-rolled JSON-RPC so
//! they depend only on `serde_json` + `std`.

pub mod lsp;
pub mod mcp;
