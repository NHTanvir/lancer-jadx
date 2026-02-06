//! Error types for DEX parsing and IR construction.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DexError {
    #[error("unexpected end of data: needed {needed} bytes at offset {offset}, have {available}")]
    Eof {
        offset: usize,
        needed: usize,
        available: usize,
    },
    #[error("bad DEX magic: {0:?}")]
    BadMagic([u8; 8]),
    #[error("unsupported DEX version: {0}")]
    UnsupportedVersion(u32),
    #[error("invalid index: {kind} index {idx} out of range (len {len})")]
    BadIndex {
        kind: &'static str,
        idx: usize,
        len: usize,
    },
    #[error("invalid uleb128/sleb128 at offset {0}")]
    BadLeb(usize),
    #[error("invalid MUTF-8 string at offset {0}")]
    BadString(usize),
    #[error("malformed structure: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, DexError>;
