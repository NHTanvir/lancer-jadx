//! `Res_value` typed data formatting (the 8-byte value record).

use crate::pool::StringPool;

// Res_value data types.
pub const TYPE_NULL: u8 = 0x00;
pub const TYPE_REFERENCE: u8 = 0x01;
pub const TYPE_ATTRIBUTE: u8 = 0x02;
pub const TYPE_STRING: u8 = 0x03;
pub const TYPE_FLOAT: u8 = 0x04;
pub const TYPE_DIMENSION: u8 = 0x05;
pub const TYPE_FRACTION: u8 = 0x06;
pub const TYPE_INT_DEC: u8 = 0x10;
pub const TYPE_INT_HEX: u8 = 0x11;
pub const TYPE_INT_BOOLEAN: u8 = 0x12;
pub const TYPE_INT_COLOR_ARGB8: u8 = 0x1c;
pub const TYPE_INT_COLOR_RGB8: u8 = 0x1d;
pub const TYPE_INT_COLOR_ARGB4: u8 = 0x1e;
pub const TYPE_INT_COLOR_RGB4: u8 = 0x1f;

const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
const FRACTION_UNITS: [&str; 2] = ["%", "%p"];
const RADIX_MULTS: [f64; 4] = [
    0.003_906_25,
    0.000_015_258_789,
    0.000_000_059_604_645,
    0.000_000_000_232_830_64,
];

/// Format a typed `Res_value` as a human-readable string.
pub fn format(data_type: u8, data: u32, strings: &StringPool) -> String {
    match data_type {
        TYPE_NULL => "@null".to_string(),
        TYPE_REFERENCE => format!("@ref/0x{data:08x}"),
        TYPE_ATTRIBUTE => format!("?attr/0x{data:08x}"),
        TYPE_STRING => strings.get_or(data, ""),
        TYPE_FLOAT => f32::from_bits(data).to_string(),
        TYPE_DIMENSION => format_complex(data, &DIMENSION_UNITS),
        TYPE_FRACTION => format_complex(data, &FRACTION_UNITS),
        TYPE_INT_DEC => (data as i32).to_string(),
        TYPE_INT_HEX => format!("0x{data:x}"),
        TYPE_INT_BOOLEAN => {
            if data != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        TYPE_INT_COLOR_ARGB8 | TYPE_INT_COLOR_RGB8 | TYPE_INT_COLOR_ARGB4 | TYPE_INT_COLOR_RGB4 => {
            format!("#{data:08x}")
        }
        _ => format!("0x{data:x}"),
    }
}

fn format_complex(data: u32, units: &[&str]) -> String {
    let value = (data & 0xffff_ff00) as i32;
    let radix = (data >> 4) & 0x3;
    let unit = (data & 0xf) as usize;
    let val = value as f64 * RADIX_MULTS[radix as usize];
    let suffix = units.get(unit).copied().unwrap_or("");
    format!("{val}{suffix}")
}
