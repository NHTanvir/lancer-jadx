//! AI-assisted semantic renaming (optional `lancer-ai` integration).
//!
//! The decompiler feeds each obfuscated symbol's context (containing class
//! skeleton + method body + call sites) to an LLM and accepts a semantic name
//! suggestion, applied project-wide via the xref index. Requests are batched and
//! rate-limited so a 50k-method APK does not overwhelm the backend.
//!
//! This struct is the integration seam: when `lancer-ai` is wired in, implement
//! [`AiRenamer::suggest`] to call it. Offline, it returns `None` so the
//! heuristic [`super::rename::Renamer`] output is used unchanged.

#[derive(Debug, Clone)]
pub struct RenameRequest {
    pub original: String,
    pub kind: SymbolKind,
    pub class_skeleton: String,
    pub body: String,
    pub call_sites: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Class,
    Method,
    Field,
}

#[derive(Debug, Clone)]
pub struct RenameSuggestion {
    pub new_name: String,
    pub doc: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct AiRenamer {
    pub enabled: bool,
    /// Max requests per batch (rate limiting).
    pub batch_size: usize,
}

impl AiRenamer {
    pub fn new(enabled: bool) -> Self {
        AiRenamer {
            enabled,
            batch_size: 32,
        }
    }

    /// Suggest a semantic name for a symbol. Offline this is a no-op.
    pub fn suggest(&self, _req: &RenameRequest) -> Option<RenameSuggestion> {
        if !self.enabled {
            return None;
        }
        // Integration point: call `lancer-ai` here.
        None
    }

    /// Batch-suggest, preserving request order.
    pub fn suggest_batch(&self, reqs: &[RenameRequest]) -> Vec<Option<RenameSuggestion>> {
        reqs.iter().map(|r| self.suggest(r)).collect()
    }
}
