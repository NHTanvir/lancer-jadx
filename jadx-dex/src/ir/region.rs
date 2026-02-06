//! Structured-control-flow region recovery.
//!
//! Walks the CFG (using the dominator / post-dominator trees and natural-loop
//! info) to recover an if/else/while/switch region tree. Reducible control flow
//! is recovered structurally; irreducible or otherwise unstructurable edges
//! degrade to `Goto` markers (the code generator renders these as labelled
//! comments, mirroring jadx's "could not structure" fallback).

use super::block::{Cfg, EdgeKind};
use super::loops::{find_loops, LoopInfo};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub enum Region {
    /// Emit a basic block's statements (terminator handled by the structurer).
    Block(usize),
    Seq(Vec<Region>),
    If {
        cond_block: usize,
        then_branch: Box<Region>,
        else_branch: Option<Box<Region>>,
    },
    Loop {
        header: usize,
        body: Box<Region>,
    },
    Switch {
        block: usize,
        cases: Vec<SwitchCase>,
    },
    Break,
    Continue,
    /// Unstructurable jump target (rendered as a labelled comment).
    Goto(usize),
    Empty,
}

#[derive(Debug, Clone)]
pub struct SwitchCase {
    pub keys: Vec<i32>,
    pub is_default: bool,
    pub body: Region,
}

#[derive(Clone, Copy)]
struct Ctx {
    loop_header: Option<usize>,
    loop_exit: Option<usize>,
}

struct Structurer<'a> {
    cfg: &'a Cfg,
    loop_headers: HashMap<usize, LoopInfo>,
    visited: HashSet<usize>,
    active: HashSet<usize>,
    steps: usize,
    step_limit: usize,
}

/// Build the region tree for a method's CFG.
pub fn structure(cfg: &Cfg) -> Region {
    if cfg.is_empty() {
        return Region::Empty;
    }
    let loops = find_loops(cfg);
    let mut by_header: HashMap<usize, LoopInfo> = HashMap::new();
    for l in loops {
        // Keep the largest body per header (outermost natural loop).
        by_header
            .entry(l.header)
            .and_modify(|cur| {
                if l.body.len() > cur.body.len() {
                    *cur = l.clone();
                }
            })
            .or_insert(l);
    }
    let mut s = Structurer {
        cfg,
        loop_headers: by_header,
        visited: HashSet::new(),
        active: HashSet::new(),
        steps: 0,
        step_limit: cfg.len() * 8 + 1024,
    };
    let ctx = Ctx {
        loop_header: None,
        loop_exit: None,
    };
    s.build(Some(cfg.entry), None, ctx)
}

impl<'a> Structurer<'a> {
    fn build(&mut self, mut cur: Option<usize>, stop: Option<usize>, ctx: Ctx) -> Region {
        let mut items: Vec<Region> = Vec::new();
        while let Some(c) = cur {
            self.steps += 1;
            if self.steps > self.step_limit {
                items.push(Region::Goto(c));
                break;
            }
            if Some(c) == stop {
                break;
            }
            if ctx.loop_exit == Some(c) {
                items.push(Region::Break);
                break;
            }
            if self.active.contains(&c) {
                if ctx.loop_header == Some(c) {
                    items.push(Region::Continue);
                } else {
                    items.push(Region::Goto(c));
                }
                break;
            }
            if self.visited.contains(&c) {
                items.push(Region::Goto(c));
                break;
            }

            // Loop entry.
            if self.loop_headers.contains_key(&c) && !self.active.contains(&c) {
                let li = self.loop_headers.get(&c).cloned().unwrap();
                let exit = self.loop_exit(&li);
                let body = self.build_loop(c, exit);
                items.push(Region::Loop {
                    header: c,
                    body: Box::new(body),
                });
                cur = exit;
                continue;
            }

            let (region, next) = self.process_node(c, ctx);
            items.push(region);
            cur = next;
        }
        flatten(items)
    }

    fn build_loop(&mut self, header: usize, exit: Option<usize>) -> Region {
        self.active.insert(header);
        let ctx = Ctx {
            loop_header: Some(header),
            loop_exit: exit,
        };
        let (head_region, next) = self.process_node(header, ctx);
        let mut items = vec![head_region];
        if let Some(n) = next {
            items.push(self.build(Some(n), None, ctx));
        }
        self.active.remove(&header);
        flatten(items)
    }

    /// Emit a single block plus its immediate control structure. Returns the
    /// region and the block to continue from (the structured "join" point).
    fn process_node(&mut self, c: usize, ctx: Ctx) -> (Region, Option<usize>) {
        self.visited.insert(c);
        let block = self.cfg.block(c);

        if block.is_exit() {
            return (Region::Block(c), None);
        }

        if block.ends_with_if() {
            let merge = self.cfg.ipdom(c);
            let mut then_t = None;
            let mut else_t = None;
            for s in &block.succs {
                match s.kind {
                    EdgeKind::IfThen => then_t = Some(s.block),
                    EdgeKind::IfElse => else_t = Some(s.block),
                    _ => {}
                }
            }
            let then_branch = Box::new(self.build(then_t, merge, ctx));
            let else_branch = match else_t {
                Some(e) if Some(e) != merge => Some(Box::new(self.build(Some(e), merge, ctx))),
                _ => None,
            };
            return (
                Region::If {
                    cond_block: c,
                    then_branch,
                    else_branch,
                },
                merge,
            );
        }

        if block.ends_with_switch() {
            let merge = self.cfg.ipdom(c);
            // Group keys that share a target block.
            let mut order: Vec<usize> = Vec::new();
            let mut by_target: HashMap<usize, (Vec<i32>, bool)> = HashMap::new();
            for s in &block.succs {
                if let EdgeKind::Switch(key) = s.kind {
                    let entry = by_target.entry(s.block).or_insert_with(|| {
                        order.push(s.block);
                        (Vec::new(), false)
                    });
                    match key {
                        Some(k) => entry.0.push(k),
                        None => entry.1 = true,
                    }
                }
            }
            let mut cases = Vec::new();
            for t in order {
                let (keys, is_default) = by_target.remove(&t).unwrap_or((Vec::new(), false));
                let body = self.build(Some(t), merge, ctx);
                cases.push(SwitchCase {
                    keys,
                    is_default,
                    body,
                });
            }
            return (Region::Switch { block: c, cases }, merge);
        }

        // goto / fall-through: continue at the single successor.
        let next = block.succs.first().map(|s| s.block);
        (Region::Block(c), next)
    }

    /// Determine the block control transfers to when leaving a loop.
    fn loop_exit(&self, li: &LoopInfo) -> Option<usize> {
        let mut exits: Vec<usize> = Vec::new();
        for &b in &li.body {
            for s in self.cfg.succs(b) {
                if !li.body.contains(&s.block) {
                    exits.push(s.block);
                }
            }
        }
        exits.sort_by_key(|&b| self.cfg.block(b).start_off);
        exits.dedup();
        exits.first().copied()
    }
}

fn flatten(mut items: Vec<Region>) -> Region {
    items.retain(|r| !matches!(r, Region::Empty));
    match items.len() {
        0 => Region::Empty,
        1 => items.pop().unwrap(),
        _ => Region::Seq(items),
    }
}

/// Convenience re-export so callers can pull loop maps if needed.
pub use super::loops::{find_loops as recover_loops, header_of as loop_header_map};
