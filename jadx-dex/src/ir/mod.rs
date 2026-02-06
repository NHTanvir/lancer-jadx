//! High-level intermediate representation: CFG, SSA, loops, try-regions, and the
//! structured region tree used by the code generators.

pub mod block;
pub mod loops;
pub mod region;
pub mod ssa;
pub mod tryblock;

pub use block::{build_cfg, Block, Cfg, EdgeKind, Succ};
pub use loops::{find_loops, header_of, LoopInfo};
pub use region::{structure, Region, SwitchCase};
pub use ssa::{build_ssa, def_reg, use_regs, SsaInfo};
pub use tryblock::{build_try_regions, CatchBranch, TryRegion};

use crate::code::CodeItem;
use crate::insn::{decode_method, Insn};

/// The complete lowered IR for one method.
pub struct MethodIr {
    pub insns: Vec<Insn>,
    pub cfg: Cfg,
    pub ssa: SsaInfo,
    pub region: Region,
    pub try_regions: Vec<TryRegion>,
}

/// Run the full DEX→IR pipeline for a single method's code item:
/// decode → CFG → SSA scaffolding → try-regions → structured regions.
pub fn lower(code: &CodeItem) -> MethodIr {
    let insns = decode_method(&code.insns);
    let try_regions = build_try_regions(&code.tries);
    let cfg = build_cfg(&insns, &code.tries);
    let ssa = build_ssa(&cfg);
    let region = structure(&cfg);
    MethodIr {
        insns,
        cfg,
        ssa,
        region,
        try_regions,
    }
}
