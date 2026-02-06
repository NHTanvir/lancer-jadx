//! jadx-core — orchestration core for lancer-jadx.
//!
//! Ties together DEX/resource parsing (`jadx-dex`, `jadx-resources`), the Java +
//! Kotlin code generators, the deobfuscator, the cross-reference index, and the
//! findings/report layer behind a single [`Jadx`] orchestrator.

pub mod args;
pub mod codegen;
pub mod decompiler;
pub mod deobf;
pub mod input;
pub mod report;
pub mod xref;

pub use args::{DecompilerBackend, JadxArgs, OutputFormat, RenameFlags};
pub use decompiler::{DecompiledClass, Jadx};
pub use report::{Finding, Severity};
pub use xref::XrefIndex;

/// Crate version (mirrors the upstream parity baseline noted in the plan).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Upstream jadx version this clone targets for parity.
pub const UPSTREAM_PARITY: &str = "1.5.5";
