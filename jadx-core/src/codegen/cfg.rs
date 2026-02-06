//! Per-method control-flow-graph emission in Graphviz DOT format.
//!
//! Backs the upstream `--cfg` / `--raw-cfg` flags: for every method that carries
//! a code item we lower it through the `jadx-dex` IR pipeline and serialise the
//! basic-block graph (with typed edges) as a `.dot` document that the GUI or any
//! Graphviz front-end can render. `--cfg` shows opcode mnemonics per block;
//! `--raw-cfg` shows the fully decoded instruction text.

use jadx_dex::ir::block::EdgeKind;
use jadx_dex::ir::{self};
use jadx_dex::{DexClass, DexFile, DexMethodEntry, IndexKind, Insn};

/// One rendered method graph: a filesystem-safe label and the DOT source.
pub struct MethodGraph {
    pub label: String,
    pub dot: String,
}

/// Emit a DOT control-flow graph for every method of `class` that has code.
/// When `raw` is true, each block lists its full decoded instructions;
/// otherwise only the opcode mnemonics are shown.
pub fn class_cfgs_dot(dex: &DexFile, class: &DexClass, raw: bool) -> Vec<MethodGraph> {
    let class_name = dex.class_name(class);
    let simple = jadx_dex::descriptor::simple_name(&class_name);
    class
        .direct_methods
        .iter()
        .chain(class.virtual_methods.iter())
        .filter_map(|m| method_cfg_dot(dex, &simple, m, raw))
        .collect()
}

fn method_cfg_dot(
    dex: &DexFile,
    class_simple: &str,
    m: &DexMethodEntry,
    raw: bool,
) -> Option<MethodGraph> {
    let code = m.code.as_ref()?;
    let mref = dex.method_entry_ref(m);
    let ir = ir::lower(code);

    let title = format!("{class_simple}.{}", mref.name);
    let signature = format!(
        "{} {}({})",
        mref.return_type,
        title,
        mref.params.join(", ")
    );

    let mut dot = String::new();
    dot.push_str(&format!("digraph \"{}\" {{\n", dot_escape(&title)));
    dot.push_str(&format!(
        "  graph [label=\"{}\", labelloc=t];\n",
        dot_escape(&signature)
    ));
    dot.push_str("  node [shape=box, fontname=\"monospace\", fontsize=10];\n");

    for b in &ir.cfg.blocks {
        let mut label = format!("B{} @{:04x}", b.id, b.start_off);
        for insn in &b.insns {
            label.push_str("\\l");
            if raw {
                label.push_str(&dot_escape(&insn_text(insn)));
            } else {
                label.push_str(&dot_escape(insn.name));
            }
        }
        label.push_str("\\l");
        dot.push_str(&format!("  b{} [label=\"{}\"];\n", b.id, label));
    }

    for b in &ir.cfg.blocks {
        for s in &b.succs {
            let lbl = edge_label(&s.kind);
            if lbl.is_empty() {
                dot.push_str(&format!("  b{} -> b{};\n", b.id, s.block));
            } else {
                dot.push_str(&format!(
                    "  b{} -> b{} [label=\"{}\"];\n",
                    b.id, s.block, lbl
                ));
            }
        }
    }
    dot.push_str("}\n");

    Some(MethodGraph {
        label: sanitize(&format!("{class_simple}.{}", mref.name)),
        dot,
    })
}

/// Render a single decoded instruction as a compact one-liner.
fn insn_text(insn: &Insn) -> String {
    let mut s = format!("{:04x}: {}", insn.offset, insn.name);
    for r in &insn.regs {
        s.push_str(&format!(" v{r}"));
    }
    match insn.index_kind {
        IndexKind::None => {
            if insn.literal != 0 {
                s.push_str(&format!(" #{}", insn.literal));
            }
        }
        _ => s.push_str(&format!(" @{}", insn.index)),
    }
    if let Some(t) = insn.target {
        s.push_str(&format!(" -> {t:04x}"));
    }
    s
}

fn edge_label(kind: &EdgeKind) -> String {
    match kind {
        EdgeKind::Fall => String::new(),
        EdgeKind::IfThen => "then".to_string(),
        EdgeKind::IfElse => "else".to_string(),
        EdgeKind::Goto => "goto".to_string(),
        EdgeKind::Switch(Some(key)) => format!("case {key}"),
        EdgeKind::Switch(None) => "default".to_string(),
    }
}

/// Escape a string for inclusion inside a DOT double-quoted label. The literal
/// `\l` line separators added by the caller are preserved (they are appended
/// after escaping each content fragment).
fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', " ")
        .replace('\r', "")
}

/// Make a label safe to use as a file-name component.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' { c } else { '_' })
        .collect()
}
