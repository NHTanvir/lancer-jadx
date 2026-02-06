//! Try/catch table → lexical try-region recovery.
//!
//! DEX stores exception handling as a flat table of `(start, count, handler)`
//! ranges. To emit `try { } catch { }` we group ranges and resolve handler
//! addresses to instruction offsets.

use crate::code::TryItem;

#[derive(Debug, Clone)]
pub struct CatchBranch {
    /// Caught exception type index (None = catch-all / `finally`).
    pub type_idx: Option<u32>,
    /// Handler start offset (code units).
    pub handler_off: u32,
}

#[derive(Debug, Clone)]
pub struct TryRegion {
    pub start_off: u32,
    pub end_off: u32,
    pub catches: Vec<CatchBranch>,
}

impl TryRegion {
    pub fn contains(&self, off: u32) -> bool {
        off >= self.start_off && off < self.end_off
    }
}

/// Convert the raw try table into lexical try regions, sorted by start.
pub fn build_try_regions(tries: &[TryItem]) -> Vec<TryRegion> {
    let mut regions: Vec<TryRegion> = tries
        .iter()
        .map(|t| {
            let mut catches: Vec<CatchBranch> = t
                .handler
                .catches
                .iter()
                .map(|c| CatchBranch {
                    type_idx: Some(c.type_idx),
                    handler_off: c.addr,
                })
                .collect();
            if let Some(ca) = t.handler.catch_all {
                catches.push(CatchBranch {
                    type_idx: None,
                    handler_off: ca,
                });
            }
            TryRegion {
                start_off: t.start_addr,
                end_off: t.end_addr(),
                catches,
            }
        })
        .collect();
    regions.sort_by_key(|r| (r.start_off, std::cmp::Reverse(r.end_off)));
    regions
}

/// Offsets that begin an exception handler (so the structurer can label them).
pub fn handler_offsets(regions: &[TryRegion]) -> Vec<u32> {
    let mut offs = Vec::new();
    for r in regions {
        for c in &r.catches {
            offs.push(c.handler_off);
        }
    }
    offs.sort_unstable();
    offs.dedup();
    offs
}
