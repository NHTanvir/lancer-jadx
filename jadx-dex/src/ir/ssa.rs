//! SSA construction over Dalvik registers (dominance frontier + phi placement).
//!
//! This builds the classic Cytron et al. SSA scaffolding: dominance frontiers,
//! iterated phi insertion, and per-register versioning. The register def/use
//! model is approximate (DEX has no single canonical "dest" bit), so this is
//! used by the code generators for variable-naming and copy-propagation hints
//! rather than as a verified optimisation IR.

use super::block::Cfg;
use crate::insn::Insn;
use std::collections::{HashMap, HashSet};

/// Register written by an instruction (its destination), if any.
pub fn def_reg(insn: &Insn) -> Option<u16> {
    let op = insn.opcode;
    let writes = matches!(op,
        0x01..=0x0d            // move / move-result / move-exception
        | 0x12..=0x1c          // const family
        | 0x1f                 // check-cast (narrows type of reg)
        | 0x20 | 0x21          // instance-of / array-length
        | 0x22 | 0x23          // new-instance / new-array
        | 0x44..=0x4a          // aget family
        | 0x52..=0x58          // iget family
        | 0x60..=0x66          // sget family
        | 0x7b..=0x8f          // unary / conversions
        | 0x90..=0xcf          // binary + 2addr
        | 0xd0..=0xe2          // lit16 / lit8
        | 0x2d..=0x31          // cmp family
        | 0xfe | 0xff          // const-method-handle / const-method-type
    );
    if writes {
        insn.regs.first().copied()
    } else {
        None
    }
}

/// Registers read (used) by an instruction.
pub fn use_regs(insn: &Insn) -> Vec<u16> {
    let op = insn.opcode;
    match op {
        // Stores: all operand registers are reads.
        0x4b..=0x51 | 0x59..=0x5f | 0x67..=0x6d => insn.regs.clone(),
        // Invokes / filled-new-array: all argument registers are reads.
        0x24 | 0x25 | 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd => insn.regs.clone(),
        // if-test (two-reg) / cmp: all operands read.
        0x32..=0x37 | 0x2d..=0x31 => insn.regs.clone(),
        // Single-reg tests / throw / monitor / switch / return-value.
        0x38..=0x3d | 0x27 | 0x1d | 0x1e | 0x2b | 0x2c | 0x0f..=0x11 => insn.regs.clone(),
        // Anything with a destination: operands after the first are reads.
        _ => {
            if def_reg(insn).is_some() && insn.regs.len() > 1 {
                insn.regs[1..].to_vec()
            } else {
                Vec::new()
            }
        }
    }
}

/// Compute dominance frontiers for every block.
pub fn dominance_frontiers(cfg: &Cfg) -> Vec<HashSet<usize>> {
    let n = cfg.len();
    let mut df: Vec<HashSet<usize>> = vec![HashSet::new(); n];
    for b in 0..n {
        let preds = cfg.preds(b);
        if preds.len() >= 2 {
            let idom_b = cfg.idom(b);
            for &p in preds {
                let mut runner = p;
                while Some(runner) != idom_b {
                    df[runner].insert(b);
                    match cfg.idom(runner) {
                        Some(d) if d != runner => runner = d,
                        _ => break,
                    }
                }
            }
        }
    }
    df
}

#[derive(Debug, Default, Clone)]
pub struct SsaInfo {
    /// For each block, the registers that receive a phi function.
    pub phis: HashMap<usize, HashSet<u16>>,
    /// Total number of distinct definitions per register (a versioning hint).
    pub versions: HashMap<u16, u32>,
}

/// Build SSA scaffolding: place phi functions at iterated dominance frontiers.
pub fn build_ssa(cfg: &Cfg) -> SsaInfo {
    let n = cfg.len();
    if n == 0 {
        return SsaInfo::default();
    }
    let df = dominance_frontiers(cfg);

    // Blocks that define each register.
    let mut def_blocks: HashMap<u16, HashSet<usize>> = HashMap::new();
    let mut versions: HashMap<u16, u32> = HashMap::new();
    for b in 0..n {
        for insn in &cfg.block(b).insns {
            if let Some(r) = def_reg(insn) {
                def_blocks.entry(r).or_default().insert(b);
                *versions.entry(r).or_insert(0) += 1;
            }
        }
    }

    let mut phis: HashMap<usize, HashSet<u16>> = HashMap::new();
    for (&reg, defs) in &def_blocks {
        let mut worklist: Vec<usize> = defs.iter().copied().collect();
        let mut has_phi: HashSet<usize> = HashSet::new();
        let mut processed: HashSet<usize> = defs.iter().copied().collect();
        while let Some(b) = worklist.pop() {
            for &y in &df[b] {
                if has_phi.insert(y) {
                    phis.entry(y).or_default().insert(reg);
                    if processed.insert(y) {
                        worklist.push(y);
                    }
                }
            }
        }
    }

    SsaInfo { phis, versions }
}
