//! Deobfuscation: heuristic renaming + optional AI-assisted renaming.

pub mod ai_rename;
pub mod rename;

pub use ai_rename::{AiRenamer, RenameRequest, RenameSuggestion, SymbolKind};
pub use rename::Renamer;
