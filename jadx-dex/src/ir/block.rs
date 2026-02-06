//! Basic-block control-flow graph with dominator + post-dominator trees.

use crate::code::TryItem;
use crate::insn::{Insn, Payload};
use crate::opcodes;
use petgraph::algo::dominators::simple_fast;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::{BTreeSet, HashMap};

/// The kind of control-flow edge between two basic blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    /// Sequential fall-through.
    Fall,
    /// The "taken" side of a conditional branch.
    IfThen,
    /// The "not taken" (fall-through) side of a conditional branch.
    IfElse,
    /// Unconditional goto.
    Goto,
    /// A switch case (key) or the default case (None).
    Switch(Option<i32>),
}

#[derive(Debug, Clone)]
pub struct Succ {
    pub block: usize,
    pub kind: EdgeKind,
}

#[derive(Debug, Clone)]
pub struct Block {
    pub id: usize,
    pub start_off: u32,
    pub insns: Vec<Insn>,
    pub succs: Vec<Succ>,
    pub preds: Vec<usize>,
}

impl Block {
    pub fn last(&self) -> Option<&Insn> {
        self.insns.last()
    }
    pub fn ends_with_return(&self) -> bool {
        self.last().map(|i| opcodes::is_return(i.opcode)).unwrap_or(false)
    }
    pub fn ends_with_throw(&self) -> bool {
        self.last().map(|i| opcodes::is_throw(i.opcode)).unwrap_or(false)
    }
    pub fn ends_with_if(&self) -> bool {
        self.last().map(|i| opcodes::is_if(i.opcode)).unwrap_or(false)
    }
    pub fn ends_with_switch(&self) -> bool {
        self.last().map(|i| opcodes::is_switch(i.opcode)).unwrap_or(false)
    }
    pub fn ends_with_goto(&self) -> bool {
        self.last().map(|i| opcodes::is_goto(i.opcode)).unwrap_or(false)
    }
    pub fn is_exit(&self) -> bool {
        self.succs.is_empty()
    }
}

pub struct Cfg {
    pub blocks: Vec<Block>,
    pub entry: usize,
    idom: Vec<Option<usize>>,
    ipdom: Vec<Option<usize>>,
}

impl Cfg {
    pub fn block(&self, id: usize) -> &Block {
        &self.blocks[id]
    }
    pub fn len(&self) -> usize {
        self.blocks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }
    pub fn idom(&self, id: usize) -> Option<usize> {
        self.idom.get(id).copied().flatten()
    }
    pub fn ipdom(&self, id: usize) -> Option<usize> {
        self.ipdom.get(id).copied().flatten()
    }
    pub fn succs(&self, id: usize) -> &[Succ] {
        &self.blocks[id].succs
    }
    pub fn preds(&self, id: usize) -> &[usize] {
        &self.blocks[id].preds
    }

    /// Does block `a` dominate block `b`?
    pub fn dominates(&self, a: usize, b: usize) -> bool {
        if a == b {
            return true;
        }
        let mut cur = b;
        while let Some(d) = self.idom(cur) {
            if d == a {
                return true;
            }
            if d == cur {
                break;
            }
            cur = d;
        }
        false
    }
}

/// Build the CFG from a method's decoded instructions and try table.
pub fn build_cfg(insns: &[Insn], tries: &[TryItem]) -> Cfg {
    // Map every (non-payload) instruction offset to its index, and collect
    // payloads keyed by offset for switch resolution.
    let mut payloads: HashMap<u32, &Payload> = HashMap::new();
    let mut real: Vec<&Insn> = Vec::new();
    for insn in insns {
        if insn.is_payload() {
            if let Some(p) = &insn.payload {
                payloads.insert(insn.offset, p);
            }
        } else {
            real.push(insn);
        }
    }
    if real.is_empty() {
        return Cfg {
            blocks: Vec::new(),
            entry: 0,
            idom: Vec::new(),
            ipdom: Vec::new(),
        };
    }

    // Collect block leaders.
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    leaders.insert(real[0].offset);
    for (i, insn) in real.iter().enumerate() {
        if let Some(t) = insn.target {
            leaders.insert(t);
        }
        if opcodes::is_switch(insn.opcode) {
            if let Some(off) = insn.target {
                add_switch_targets(&mut leaders, &payloads, insn.offset, off);
            }
        }
        if opcodes::is_block_end(insn.opcode) {
            if let Some(next) = real.get(i + 1) {
                leaders.insert(next.offset);
            }
        }
    }
    for t in tries {
        leaders.insert(t.start_addr);
        leaders.insert(t.end_addr());
        if let Some(ca) = t.handler.catch_all {
            leaders.insert(ca);
        }
        for c in &t.handler.catches {
            leaders.insert(c.addr);
        }
    }

    let leader_list: Vec<u32> = leaders.iter().copied().collect();
    let mut off_to_block: HashMap<u32, usize> = HashMap::new();
    for (bid, &off) in leader_list.iter().enumerate() {
        off_to_block.insert(off, bid);
    }

    // Partition instructions into blocks.
    let mut blocks: Vec<Block> = leader_list
        .iter()
        .enumerate()
        .map(|(id, &start_off)| Block {
            id,
            start_off,
            insns: Vec::new(),
            succs: Vec::new(),
            preds: Vec::new(),
        })
        .collect();

    // Assign each real insn to the block whose range contains its offset.
    let mut cur_block = 0usize;
    let mut next_leader_idx = 1usize;
    for insn in &real {
        while next_leader_idx < leader_list.len() && insn.offset >= leader_list[next_leader_idx] {
            cur_block = next_leader_idx;
            next_leader_idx += 1;
        }
        blocks[cur_block].insns.push((*insn).clone());
    }

    // Wire successors.
    let nblocks = blocks.len();
    for bid in 0..nblocks {
        let succs = compute_succs(&blocks[bid], &off_to_block, &payloads, &leader_list, bid);
        blocks[bid].succs = succs;
    }
    // Predecessors.
    for bid in 0..nblocks {
        let succ_ids: Vec<usize> = blocks[bid].succs.iter().map(|s| s.block).collect();
        for sid in succ_ids {
            if sid < nblocks {
                blocks[sid].preds.push(bid);
            }
        }
    }

    let entry = 0;
    let (idom, ipdom) = compute_dominators(&blocks, entry);
    Cfg {
        blocks,
        entry,
        idom,
        ipdom,
    }
}

fn add_switch_targets(
    leaders: &mut BTreeSet<u32>,
    payloads: &HashMap<u32, &Payload>,
    switch_off: u32,
    payload_off: u32,
) {
    if let Some(p) = payloads.get(&payload_off) {
        match p {
            Payload::PackedSwitch { targets, .. } | Payload::SparseSwitch { targets, .. } => {
                for &rel in targets {
                    leaders.insert((switch_off as i64 + rel as i64) as u32);
                }
            }
            _ => {}
        }
    }
}

fn compute_succs(
    block: &Block,
    off_to_block: &HashMap<u32, usize>,
    payloads: &HashMap<u32, &Payload>,
    leader_list: &[u32],
    bid: usize,
) -> Vec<Succ> {
    let mut succs = Vec::new();
    let last = match block.last() {
        Some(l) => l,
        None => return succs,
    };
    let fallthrough_off = leader_list.get(bid + 1).copied();

    if opcodes::is_return(last.opcode) || opcodes::is_throw(last.opcode) {
        // no normal successors
    } else if opcodes::is_goto(last.opcode) {
        if let Some(t) = last.target.and_then(|o| off_to_block.get(&o)) {
            succs.push(Succ {
                block: *t,
                kind: EdgeKind::Goto,
            });
        }
    } else if opcodes::is_if(last.opcode) {
        if let Some(t) = last.target.and_then(|o| off_to_block.get(&o)) {
            succs.push(Succ {
                block: *t,
                kind: EdgeKind::IfThen,
            });
        }
        if let Some(f) = fallthrough_off.and_then(|o| off_to_block.get(&o)) {
            succs.push(Succ {
                block: *f,
                kind: EdgeKind::IfElse,
            });
        }
    } else if opcodes::is_switch(last.opcode) {
        if let Some(payload_off) = last.target {
            if let Some(p) = payloads.get(&payload_off) {
                let mut push_case = |key: Option<i32>, rel: i32| {
                    let dst = (last.offset as i64 + rel as i64) as u32;
                    if let Some(b) = off_to_block.get(&dst) {
                        succs.push(Succ {
                            block: *b,
                            kind: EdgeKind::Switch(key),
                        });
                    }
                };
                match p {
                    Payload::PackedSwitch { first_key, targets } => {
                        for (i, &rel) in targets.iter().enumerate() {
                            push_case(Some(first_key + i as i32), rel);
                        }
                    }
                    Payload::SparseSwitch { keys, targets } => {
                        for (&k, &rel) in keys.iter().zip(targets.iter()) {
                            push_case(Some(k), rel);
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(f) = fallthrough_off.and_then(|o| off_to_block.get(&o)) {
            succs.push(Succ {
                block: *f,
                kind: EdgeKind::Switch(None),
            });
        }
    } else {
        // Ordinary fall-through.
        if let Some(f) = fallthrough_off.and_then(|o| off_to_block.get(&o)) {
            succs.push(Succ {
                block: *f,
                kind: EdgeKind::Fall,
            });
        }
    }
    succs
}

fn compute_dominators(blocks: &[Block], entry: usize) -> (Vec<Option<usize>>, Vec<Option<usize>>) {
    let n = blocks.len();
    // Forward graph: NodeIndex(i) <-> block i.
    let mut g: DiGraph<usize, ()> = DiGraph::new();
    let nodes: Vec<NodeIndex> = (0..n).map(|i| g.add_node(i)).collect();
    for b in blocks {
        for s in &b.succs {
            if s.block < n {
                g.add_edge(nodes[b.id], nodes[s.block], ());
            }
        }
    }
    let mut idom = vec![None; n];
    let dom = simple_fast(&g, nodes[entry]);
    for i in 0..n {
        if let Some(d) = dom.immediate_dominator(nodes[i]) {
            idom[i] = Some(g[d]);
        }
    }

    // Reverse graph with a virtual exit for post-dominators.
    let mut rg: DiGraph<usize, ()> = DiGraph::new();
    let rnodes: Vec<NodeIndex> = (0..n).map(|i| rg.add_node(i)).collect();
    let exit = rg.add_node(usize::MAX);
    for b in blocks {
        for s in &b.succs {
            if s.block < n {
                rg.add_edge(rnodes[s.block], rnodes[b.id], ());
            }
        }
        if b.is_exit() {
            rg.add_edge(exit, rnodes[b.id], ());
        }
    }
    let mut ipdom = vec![None; n];
    let pdom = simple_fast(&rg, exit);
    for i in 0..n {
        if let Some(d) = pdom.immediate_dominator(rnodes[i]) {
            let w = rg[d];
            if w != usize::MAX {
                ipdom[i] = Some(w);
            }
        }
    }
    (idom, ipdom)
}
