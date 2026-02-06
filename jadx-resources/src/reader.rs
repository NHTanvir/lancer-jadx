//! A small little-endian cursor for Android resource chunk formats.

use crate::error::{ResError, Result};

pub struct Buf<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Buf<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Buf { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Buf { data, pos }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }
    pub fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.data.len() {
            Err(ResError::Eof(self.pos))
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

    pub fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
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

    /// Read a u16/u32 at an absolute offset without moving the cursor.
    pub fn u32_at(&self, off: usize) -> Result<u32> {
        if off + 4 > self.data.len() {
            return Err(ResError::Eof(off));
        }
        Ok(u32::from_le_bytes([
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ]))
    }

    pub fn u16_at(&self, off: usize) -> Result<u16> {
        if off + 2 > self.data.len() {
            return Err(ResError::Eof(off));
        }
        Ok(u16::from_le_bytes([self.data[off], self.data[off + 1]]))
    }
}

/// A parsed chunk header (`type`, `header_size`, `chunk_size`).
#[derive(Debug, Clone, Copy)]
pub struct ChunkHeader {
    pub type_id: u16,
    pub header_size: u16,
    pub chunk_size: u32,
    pub start: usize,
}

impl ChunkHeader {
    pub fn read(b: &mut Buf) -> Result<ChunkHeader> {
        let start = b.pos;
        let type_id = b.u16()?;
        let header_size = b.u16()?;
        let chunk_size = b.u32()?;
        Ok(ChunkHeader {
            type_id,
            header_size,
            chunk_size,
            start,
        })
    }

    pub fn end(&self) -> usize {
        self.start + self.chunk_size as usize
    }
}
