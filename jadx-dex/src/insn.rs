//! Decode raw DEX code units into structured instructions.

use crate::opcodes::{op_info, IndexKind, InsnFormat};

/// A trailing payload pseudo-instruction (switch tables / array data).
#[derive(Debug, Clone)]
pub enum Payload {
    PackedSwitch {
        first_key: i32,
        /// Relative (code-unit) branch targets, one per key.
        targets: Vec<i32>,
    },
    SparseSwitch {
        keys: Vec<i32>,
        targets: Vec<i32>,
    },
    FillArray {
        element_width: u16,
        data: Vec<u8>,
    },
}

/// A decoded DEX instruction.
#[derive(Debug, Clone)]
pub struct Insn {
    /// Offset within the method, in 16-bit code units.
    pub offset: u32,
    pub opcode: u8,
    pub name: &'static str,
    pub format: InsnFormat,
    /// Register operands, in source order.
    pub regs: Vec<u16>,
    /// Literal/const operand (sign-extended where applicable).
    pub literal: i64,
    /// Constant-pool index (string/type/field/method/...).
    pub index: u32,
    pub index_kind: IndexKind,
    /// Secondary index (proto for invoke-polymorphic).
    pub proto_index: u32,
    /// Absolute branch/switch target offset (code units), if any.
    pub target: Option<u32>,
    /// Width consumed, in code units.
    pub width: usize,
    pub payload: Option<Payload>,
}

impl Insn {
    pub fn is_payload(&self) -> bool {
        self.format == InsnFormat::Payload
    }
}

#[inline]
fn at(units: &[u16], i: usize) -> u16 {
    units.get(i).copied().unwrap_or(0)
}

#[inline]
fn i32from(lo: u16, hi: u16) -> i32 {
    (((hi as u32) << 16) | lo as u32) as i32
}

#[inline]
fn sx4(n: u16) -> i64 {
    let n = (n & 0xf) as i64;
    if n & 0x8 != 0 {
        n - 16
    } else {
        n
    }
}

#[inline]
fn sx8(n: u16) -> i64 {
    (n as u8 as i8) as i64
}

/// Decode a method's instruction stream into structured `Insn`s.
pub fn decode_method(units: &[u16]) -> Vec<Insn> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < units.len() {
        let u0 = units[off];
        let op = (u0 & 0xff) as u8;

        // Trailing payload pseudo-instructions (identified by full first unit).
        if op == 0x00 && (u0 >> 8) != 0 {
            if let Some(insn) = decode_payload(units, off) {
                let w = insn.width;
                out.push(insn);
                off += w.max(1);
                continue;
            }
        }

        let info = op_info(op);
        let mut insn = Insn {
            offset: off as u32,
            opcode: op,
            name: info.name,
            format: info.format,
            regs: Vec::new(),
            literal: 0,
            index: 0,
            index_kind: info.index,
            proto_index: 0,
            target: None,
            width: info.format.width(),
            payload: None,
        };
        decode_operands(&mut insn, units, off);
        let w = insn.width.max(1);
        out.push(insn);
        off += w;
    }
    out
}

fn decode_operands(insn: &mut Insn, units: &[u16], off: usize) {
    use InsnFormat::*;
    let u0 = at(units, off);
    let aa = ((u0 >> 8) & 0xff) as u16;
    let a_nib = (u0 >> 8) & 0xf;
    let b_nib = (u0 >> 12) & 0xf;
    match insn.format {
        F10x | F20bc | Payload | Unused => {}
        F12x => {
            insn.regs = vec![a_nib, b_nib];
        }
        F11n => {
            insn.regs = vec![a_nib];
            insn.literal = sx4(b_nib);
        }
        F11x => {
            insn.regs = vec![aa];
        }
        F10t => {
            let rel = (aa as u8 as i8) as i64;
            insn.target = Some((off as i64 + rel) as u32);
        }
        F20t => {
            let rel = (at(units, off + 1) as i16) as i64;
            insn.target = Some((off as i64 + rel) as u32);
        }
        F22x => {
            insn.regs = vec![aa, at(units, off + 1)];
        }
        F21t => {
            insn.regs = vec![aa];
            let rel = (at(units, off + 1) as i16) as i64;
            insn.target = Some((off as i64 + rel) as u32);
        }
        F21s => {
            insn.regs = vec![aa];
            insn.literal = (at(units, off + 1) as i16) as i64;
        }
        F21h => {
            insn.regs = vec![aa];
            let raw = at(units, off + 1) as i64;
            // const/high16 shifts into the top 16 bits of a 32-bit value;
            // const-wide/high16 into the top 16 of a 64-bit value.
            insn.literal = if insn.opcode == 0x19 {
                raw << 48
            } else {
                raw << 16
            };
        }
        F21c => {
            insn.regs = vec![aa];
            insn.index = at(units, off + 1) as u32;
        }
        F23x => {
            let u1 = at(units, off + 1);
            insn.regs = vec![aa, u1 & 0xff, (u1 >> 8) & 0xff];
        }
        F22b => {
            let u1 = at(units, off + 1);
            insn.regs = vec![aa, u1 & 0xff];
            insn.literal = sx8((u1 >> 8) & 0xff);
        }
        F22t => {
            insn.regs = vec![a_nib, b_nib];
            let rel = (at(units, off + 1) as i16) as i64;
            insn.target = Some((off as i64 + rel) as u32);
        }
        F22s => {
            insn.regs = vec![a_nib, b_nib];
            insn.literal = (at(units, off + 1) as i16) as i64;
        }
        F22c | F22cs => {
            insn.regs = vec![a_nib, b_nib];
            insn.index = at(units, off + 1) as u32;
        }
        F30t => {
            let rel = i32from(at(units, off + 1), at(units, off + 2)) as i64;
            insn.target = Some((off as i64 + rel) as u32);
        }
        F32x => {
            insn.regs = vec![at(units, off + 1), at(units, off + 2)];
        }
        F31i => {
            insn.regs = vec![aa];
            insn.literal = i32from(at(units, off + 1), at(units, off + 2)) as i64;
        }
        F31t => {
            insn.regs = vec![aa];
            let rel = i32from(at(units, off + 1), at(units, off + 2)) as i64;
            insn.target = Some((off as i64 + rel) as u32);
        }
        F31c => {
            insn.regs = vec![aa];
            insn.index = i32from(at(units, off + 1), at(units, off + 2)) as u32;
        }
        F35c | F35ms | F35mi => {
            let count = (u0 >> 12) & 0xf;
            let g = (u0 >> 8) & 0xf;
            insn.index = at(units, off + 1) as u32;
            let u2 = at(units, off + 2);
            let c = u2 & 0xf;
            let d = (u2 >> 4) & 0xf;
            let e = (u2 >> 8) & 0xf;
            let f = (u2 >> 12) & 0xf;
            let all = [c, d, e, f, g];
            insn.regs = all.iter().take(count as usize).copied().collect();
        }
        F3rc | F3rms | F3rmi => {
            let count = aa;
            insn.index = at(units, off + 1) as u32;
            let start = at(units, off + 2);
            insn.regs = (0..count).map(|i| start + i).collect();
        }
        F45cc => {
            let count = (u0 >> 12) & 0xf;
            let g = (u0 >> 8) & 0xf;
            insn.index = at(units, off + 1) as u32;
            let u2 = at(units, off + 2);
            let c = u2 & 0xf;
            let d = (u2 >> 4) & 0xf;
            let e = (u2 >> 8) & 0xf;
            let f = (u2 >> 12) & 0xf;
            let all = [c, d, e, f, g];
            insn.regs = all.iter().take(count as usize).copied().collect();
            insn.proto_index = at(units, off + 3) as u32;
        }
        F4rcc => {
            let count = aa;
            insn.index = at(units, off + 1) as u32;
            let start = at(units, off + 2);
            insn.regs = (0..count).map(|i| start + i).collect();
            insn.proto_index = at(units, off + 3) as u32;
        }
        F51l => {
            insn.regs = vec![aa];
            let lo = i32from(at(units, off + 1), at(units, off + 2)) as u32 as u64;
            let hi = i32from(at(units, off + 3), at(units, off + 4)) as u32 as u64;
            insn.literal = ((hi << 32) | lo) as i64;
        }
    }
}

fn decode_payload(units: &[u16], off: usize) -> Option<Insn> {
    let ident = at(units, off);
    let mut insn = Insn {
        offset: off as u32,
        opcode: 0,
        name: "payload",
        format: InsnFormat::Payload,
        regs: Vec::new(),
        literal: 0,
        index: 0,
        index_kind: IndexKind::None,
        proto_index: 0,
        target: None,
        width: 1,
        payload: None,
    };
    match ident {
        0x0100 => {
            // packed-switch-payload
            let size = at(units, off + 1) as usize;
            let first_key = i32from(at(units, off + 2), at(units, off + 3));
            let mut targets = Vec::with_capacity(size);
            for i in 0..size {
                let base = off + 4 + i * 2;
                targets.push(i32from(at(units, base), at(units, base + 1)));
            }
            insn.name = "packed-switch-payload";
            insn.width = (size * 2) + 4;
            insn.payload = Some(Payload::PackedSwitch { first_key, targets });
        }
        0x0200 => {
            // sparse-switch-payload
            let size = at(units, off + 1) as usize;
            let mut keys = Vec::with_capacity(size);
            for i in 0..size {
                let base = off + 2 + i * 2;
                keys.push(i32from(at(units, base), at(units, base + 1)));
            }
            let mut targets = Vec::with_capacity(size);
            for i in 0..size {
                let base = off + 2 + size * 2 + i * 2;
                targets.push(i32from(at(units, base), at(units, base + 1)));
            }
            insn.name = "sparse-switch-payload";
            insn.width = (size * 4) + 2;
            insn.payload = Some(Payload::SparseSwitch { keys, targets });
        }
        0x0300 => {
            // fill-array-data-payload
            let element_width = at(units, off + 1);
            let size = i32from(at(units, off + 2), at(units, off + 3)) as usize;
            let byte_len = size * element_width as usize;
            let unit_len = byte_len.div_ceil(2);
            let mut data = Vec::with_capacity(byte_len);
            for i in 0..unit_len {
                let w = at(units, off + 4 + i);
                data.push((w & 0xff) as u8);
                data.push((w >> 8) as u8);
            }
            data.truncate(byte_len);
            insn.name = "fill-array-data-payload";
            insn.width = 4 + unit_len;
            insn.payload = Some(Payload::FillArray {
                element_width,
                data,
            });
        }
        _ => return None,
    }
    Some(insn)
}
