//! `code_item` parsing: instructions, try/catch tables, and debug line info.

use crate::error::Result;
use crate::reader::Reader;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CatchType {
    pub type_idx: u32,
    pub addr: u32,
}

#[derive(Debug, Clone, Default)]
pub struct CatchHandler {
    pub catches: Vec<CatchType>,
    pub catch_all: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler: CatchHandler,
}

impl TryItem {
    pub fn end_addr(&self) -> u32 {
        self.start_addr + self.insn_count as u32
    }
}

#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    pub line_start: u32,
    pub param_names: Vec<Option<String>>,
    /// (instruction code-unit address, source line) positions.
    pub positions: Vec<(u32, u32)>,
}

#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub debug_info_off: u32,
    pub insns: Vec<u16>,
    pub tries: Vec<TryItem>,
    pub debug: Option<DebugInfo>,
}

impl CodeItem {
    pub fn parse(r: &mut Reader, off: usize) -> Result<CodeItem> {
        r.set_pos(off);
        let registers_size = r.u16()?;
        let ins_size = r.u16()?;
        let outs_size = r.u16()?;
        let tries_size = r.u16()?;
        let debug_info_off = r.u32()?;
        let insns_size = r.u32()? as usize;
        let mut insns = Vec::with_capacity(insns_size);
        for _ in 0..insns_size {
            insns.push(r.u16()?);
        }
        let mut tries = Vec::new();
        if tries_size > 0 {
            // padding to 4-byte alignment if insns_size is odd
            if insns_size % 2 == 1 {
                let _ = r.u16()?;
            }
            // try_item[]
            let mut raw_tries = Vec::with_capacity(tries_size as usize);
            for _ in 0..tries_size {
                let start_addr = r.u32()?;
                let insn_count = r.u16()?;
                let handler_off = r.u16()?;
                raw_tries.push((start_addr, insn_count, handler_off));
            }
            // encoded_catch_handler_list begins here
            let list_start = r.pos();
            let handlers = parse_handler_list(r, list_start)?;
            for (start_addr, insn_count, handler_off) in raw_tries {
                let handler = handlers
                    .get(&(handler_off as usize))
                    .cloned()
                    .unwrap_or_default();
                tries.push(TryItem {
                    start_addr,
                    insn_count,
                    handler,
                });
            }
        }
        Ok(CodeItem {
            registers_size,
            ins_size,
            outs_size,
            debug_info_off,
            insns,
            tries,
            debug: None,
        })
    }
}

/// Parse the `encoded_catch_handler_list`, keyed by byte offset relative to the
/// list start (which is how `try_item.handler_off` references handlers).
fn parse_handler_list(r: &mut Reader, list_start: usize) -> Result<HashMap<usize, CatchHandler>> {
    let mut map = HashMap::new();
    let count = r.uleb128()?;
    for _ in 0..count {
        let rel = r.pos() - list_start;
        let size = r.sleb128()?;
        let n = size.unsigned_abs() as usize;
        let mut catches = Vec::with_capacity(n);
        for _ in 0..n {
            let type_idx = r.uleb128()?;
            let addr = r.uleb128()?;
            catches.push(CatchType { type_idx, addr });
        }
        let catch_all = if size <= 0 {
            Some(r.uleb128()?)
        } else {
            None
        };
        map.insert(rel, CatchHandler { catches, catch_all });
    }
    Ok(map)
}

// Debug info state machine opcodes.
const DBG_END_SEQUENCE: u8 = 0x00;
const DBG_ADVANCE_PC: u8 = 0x01;
const DBG_ADVANCE_LINE: u8 = 0x02;
const DBG_START_LOCAL: u8 = 0x03;
const DBG_START_LOCAL_EXTENDED: u8 = 0x04;
const DBG_END_LOCAL: u8 = 0x05;
const DBG_RESTART_LOCAL: u8 = 0x06;
const DBG_SET_PROLOGUE_END: u8 = 0x07;
const DBG_SET_EPILOGUE_BEGIN: u8 = 0x08;
const DBG_SET_FILE: u8 = 0x09;
const DBG_FIRST_SPECIAL: u8 = 0x0a;
const DBG_LINE_BASE: i32 = -4;
const DBG_LINE_RANGE: i32 = 15;

/// Parse `debug_info_item` into line positions + parameter names.
pub fn parse_debug_info(r: &mut Reader, off: usize, strings: &[String]) -> Result<DebugInfo> {
    r.set_pos(off);
    let line_start = r.uleb128()?;
    let params = r.uleb128()? as usize;
    let mut param_names = Vec::with_capacity(params);
    for _ in 0..params {
        let idx = r.uleb128p1()?;
        param_names.push(string_opt(strings, idx));
    }

    let mut address: i64 = 0;
    let mut line: i64 = line_start as i64;
    let mut positions = Vec::new();
    loop {
        let opcode = r.u8()?;
        match opcode {
            DBG_END_SEQUENCE => break,
            DBG_ADVANCE_PC => {
                address += r.uleb128()? as i64;
            }
            DBG_ADVANCE_LINE => {
                line += r.sleb128()? as i64;
            }
            DBG_START_LOCAL => {
                let _reg = r.uleb128()?;
                let _name = r.uleb128p1()?;
                let _ty = r.uleb128p1()?;
            }
            DBG_START_LOCAL_EXTENDED => {
                let _reg = r.uleb128()?;
                let _name = r.uleb128p1()?;
                let _ty = r.uleb128p1()?;
                let _sig = r.uleb128p1()?;
            }
            DBG_END_LOCAL | DBG_RESTART_LOCAL => {
                let _reg = r.uleb128()?;
            }
            DBG_SET_PROLOGUE_END | DBG_SET_EPILOGUE_BEGIN => {}
            DBG_SET_FILE => {
                let _name = r.uleb128p1()?;
            }
            op if op >= DBG_FIRST_SPECIAL => {
                let adjusted = (op - DBG_FIRST_SPECIAL) as i32;
                line += (DBG_LINE_BASE + (adjusted % DBG_LINE_RANGE)) as i64;
                address += (adjusted / DBG_LINE_RANGE) as i64;
                positions.push((address as u32, line.max(0) as u32));
            }
            _ => break,
        }
    }

    Ok(DebugInfo {
        line_start,
        param_names,
        positions,
    })
}

fn string_opt(strings: &[String], idx: i64) -> Option<String> {
    if idx < 0 {
        None
    } else {
        strings.get(idx as usize).cloned()
    }
}
