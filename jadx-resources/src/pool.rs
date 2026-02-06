//! `ResStringPool` chunk parsing (UTF-8 and UTF-16 variants).

use crate::error::Result;
use crate::reader::Buf;

pub const RES_STRING_POOL_TYPE: u16 = 0x0001;
const UTF8_FLAG: u32 = 1 << 8;

#[derive(Debug, Clone, Default)]
pub struct StringPool {
    pub strings: Vec<String>,
}

impl StringPool {
    pub fn get(&self, idx: u32) -> Option<&str> {
        if idx == 0xffff_ffff {
            None
        } else {
            self.strings.get(idx as usize).map(|s| s.as_str())
        }
    }

    pub fn get_or(&self, idx: u32, default: &str) -> String {
        self.get(idx).unwrap_or(default).to_string()
    }

    /// Parse a string pool whose chunk begins at `offset`.
    pub fn parse(data: &[u8], offset: usize) -> Result<StringPool> {
        let mut b = Buf::at(data, offset);
        let _type = b.u16()?;
        let _header_size = b.u16()?;
        let _chunk_size = b.u32()?;
        let string_count = b.u32()? as usize;
        let _style_count = b.u32()?;
        let flags = b.u32()?;
        let strings_start = b.u32()? as usize;
        let _styles_start = b.u32()?;
        let is_utf8 = flags & UTF8_FLAG != 0;

        let mut offsets = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            offsets.push(b.u32()? as usize);
        }

        let data_base = offset + strings_start;
        let mut strings = Vec::with_capacity(string_count);
        for &so in &offsets {
            let p = data_base + so;
            let s = if is_utf8 {
                read_utf8(data, p)
            } else {
                read_utf16(data, p)
            };
            strings.push(s.unwrap_or_default());
        }
        Ok(StringPool { strings })
    }
}

fn read_len8(data: &[u8], p: &mut usize) -> usize {
    if *p >= data.len() {
        return 0;
    }
    let mut len = data[*p] as usize;
    *p += 1;
    if len & 0x80 != 0 {
        if *p >= data.len() {
            return 0;
        }
        len = ((len & 0x7f) << 8) | data[*p] as usize;
        *p += 1;
    }
    len
}

fn read_len16(data: &[u8], p: &mut usize) -> usize {
    if *p + 1 >= data.len() {
        return 0;
    }
    let mut len = u16::from_le_bytes([data[*p], data[*p + 1]]) as usize;
    *p += 2;
    if len & 0x8000 != 0 {
        if *p + 1 >= data.len() {
            return 0;
        }
        let hi = u16::from_le_bytes([data[*p], data[*p + 1]]) as usize;
        *p += 2;
        len = ((len & 0x7fff) << 16) | hi;
    }
    len
}

fn read_utf8(data: &[u8], mut p: usize) -> Option<String> {
    let _char_len = read_len8(data, &mut p);
    let byte_len = read_len8(data, &mut p);
    if p + byte_len > data.len() {
        return None;
    }
    Some(String::from_utf8_lossy(&data[p..p + byte_len]).into_owned())
}

fn read_utf16(data: &[u8], mut p: usize) -> Option<String> {
    let units = read_len16(data, &mut p);
    if p + units * 2 > data.len() {
        return None;
    }
    let mut u16s = Vec::with_capacity(units);
    for i in 0..units {
        u16s.push(u16::from_le_bytes([data[p + i * 2], data[p + i * 2 + 1]]));
    }
    Some(String::from_utf16_lossy(&u16s))
}
