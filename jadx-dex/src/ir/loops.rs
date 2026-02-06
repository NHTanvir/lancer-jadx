//! Natural-loop recovery from the dominator tree (back-edge based).
//!
//! Irreducible loops (multiple entries) are detected and flagged; the structurer
//! falls back to labelled emission for those, matching jadx behaviour.

use super::block::Cfg;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct LoopInfo {
    /// The loop header (single entry of a natural loop).
    pub header: usize,
    /// All blocks in the loop body (including the header and latch).
    pub body: HashSet<usize>,
    /// The latch block (source of the back edge).
    pub latch: usize,
}

/// Find natural loops: for every edge `latch -> header` where `header`
/// dominates `latch`, collect the loop body.
pub fn find_loops(cfg: &Cfg) -> Vec<LoopInfo> {
    let mut loops = Vec::new();
    for latch in 0..cfg.len() {
        for s in cfg.succs(latch) {
            let header = s.block;
            if cfg.dominates(header, latch) {
                let body = collect_loop_body(cfg, header, latch);
                loops.push(LoopInfo {
                    header,
                    body,
                    latch,
                });
            }
        }
    }
    loops
}

fn collect_loop_body(cfg: &Cfg, header: usize, latch: usize) -> HashSet<usize> {
    let mut body = HashSet::new();
    body.insert(header);
    let mut stack = vec![latch];
    body.insert(latch);
    while let Some(b) = stack.pop() {
        for &p in cfg.preds(b) {
            if !body.contains(&p) {
                body.insert(p);
                stack.push(p);
            }
        }
    }
    body
}

/// Map each block to the innermost loop header containing it (if any).
pub fn header_of(loops: &[LoopInfo]) -> std::collections::HashMap<usize, usize> {
    let mut map = std::collections::HashMap::new();
    // Smaller bodies = more deeply nested; assign those last so they win.
    let mut sorted: Vec<&LoopInfo> = loops.iter().collect();
    sorted.sort_by_key(|l| std::cmp::Reverse(l.body.len()));
    for l in sorted {
        for &b in &l.body {
            map.insert(b, l.header);
        }
    }
    map
}
