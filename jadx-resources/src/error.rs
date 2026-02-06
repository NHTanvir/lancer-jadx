//! Error types for resource decoding.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ResError {
    #[error("unexpected end of data at offset {0}")]
    Eof(usize),
    #[error("bad chunk: expected type 0x{expected:04x}, found 0x{found:04x} at offset {offset}")]
    BadChunk {
        expected: u16,
        found: u16,
        offset: usize,
    },
    #[error("malformed resource data: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, ResError>;
