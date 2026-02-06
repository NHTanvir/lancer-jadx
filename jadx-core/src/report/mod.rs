//! Reporting: JSON package tree + security findings (SARIF / Quark / native).

pub mod findings;
pub mod tree;

pub use findings::{
    scan_manifest, scan_sources, to_json as findings_json, to_quark, to_sarif, Finding, Severity,
};
pub use tree::{build_tree, to_json as tree_to_json, ProjectTree};
