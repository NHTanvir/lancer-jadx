//! Little-endian cursor over a DEX byte buffer, with LEB128 + MUTF-8 helpers.

use crate::error::{DexError, Result};

/// A bounds-checked, position-tracking little-endian reader.
#[derive(Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Reader { data, pos }
    }

    #[inline]
    pub fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    pub fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() {
            Err(DexError::Eof {
                offset: self.pos,
                needed: n,
                available: self.remaining(),
            })
        } else {
            Ok(())
        }
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn i8(&mut self) -> Result<i8> {
        Ok(self.u8()? as i8)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    pub fn i16(&mut self) -> Result<i16> {
        Ok(self.u16()? as i16)
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> Result<u64> {
        self.need(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_le_bytes(b))
    }

    pub fn i64(&mut self) -> Result<i64> {
        Ok(self.u64()? as i64)
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn array8(&mut self) -> Result<[u8; 8]> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.bytes(8)?);
        Ok(out)
    }

    /// Unsigned LEB128 (max 5 bytes for u32).
    pub fn uleb128(&mut self) -> Result<u32> {
        let start = self.pos;
        let mut result: u32 = 0;
        let mut shift = 0;
        loop {
            let byte = self.u8()?;
            result |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 35 {
                return Err(DexError::BadLeb(start));
            }
        }
        Ok(result)
    }

    /// uleb128p1: a uleb128 value, minus one. NO_INDEX is encoded as 0.
    pub fn uleb128p1(&mut self) -> Result<i64> {
        Ok(self.uleb128()? as i64 - 1)
    }

    /// Signed LEB128.
    pub fn sleb128(&mut self) -> Result<i32> {
        let start = self.pos;
        let mut result: i32 = 0;
        let mut shift = 0;
        loop {
            let byte = self.u8()?;
            result |= ((byte & 0x7f) as i32) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 32 && (byte & 0x40) != 0 {
                    result |= -(1i32 << shift);
                }
                break;
            }
            if shift >= 35 {
                return Err(DexError::BadLeb(start));
            }
        }
        Ok(result)
    }

    /// Read a MUTF-8 (modified UTF-8) string of `utf16_len` code units; reads
    /// until the NUL terminator. Returns a lossy-decoded Rust `String`.
    pub fn mutf8(&mut self, _utf16_len: usize) -> Result<String> {
        let start = self.pos;
        let mut bytes = Vec::new();
        loop {
            let b = self.u8()?;
            if b == 0 {
                break;
            }
            bytes.push(b);
        }
        Ok(decode_mutf8(&bytes).unwrap_or_else(|_| {
            String::from_utf8_lossy(&self.data[start..self.pos.saturating_sub(1)]).into_owned()
        }))
    }
}

/// Decode Modified UTF-8 (the JVM/Dalvik variant) into a Rust String.
pub fn decode_mutf8(bytes: &[u8]) -> Result<String> {
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let a = bytes[i];
        if a == 0 {
            break;
        } else if a < 0x80 {
            out.push(a as char);
            i += 1;
        } else if a & 0xe0 == 0xc0 {
            if i + 1 >= bytes.len() {
                return Err(DexError::BadString(i));
            }
            let b = bytes[i + 1];
            let cp = (((a & 0x1f) as u32) << 6) | ((b & 0x3f) as u32);
            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
            i += 2;
        } else if a & 0xf0 == 0xe0 {
            if i + 2 >= bytes.len() {
                return Err(DexError::BadString(i));
            }
            let b = bytes[i + 1];
            let c = bytes[i + 2];
            let cp =
                (((a & 0x0f) as u32) << 12) | (((b & 0x3f) as u32) << 6) | ((c & 0x3f) as u32);
            // Surrogate pair handling (CESU-8 style) for astral planes.
            if (0xd800..=0xdbff).contains(&cp) && i + 5 < bytes.len() {
                let d = bytes[i + 3];
                let e = bytes[i + 4];
                let f = bytes[i + 5];
                if d & 0xf0 == 0xe0 {
                    let lo = (((d & 0x0f) as u32) << 12)
                        | (((e & 0x3f) as u32) << 6)
                        | ((f & 0x3f) as u32);
                    if (0xdc00..=0xdfff).contains(&lo) {
                        let astral = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                        out.push(char::from_u32(astral).unwrap_or('\u{fffd}'));
                        i += 6;
                        continue;
                    }
                }
            }
            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
            i += 3;
        } else {
            // Invalid lead byte; emit replacement and advance.
            out.push('\u{fffd}');
            i += 1;
        }
    }
    Ok(out)
}
