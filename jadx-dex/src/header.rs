//! DEX file header parsing + multi-DEX container detection.

use crate::error::{DexError, Result};
use crate::reader::Reader;

pub const DEX_MAGIC: &[u8; 4] = b"dex\n";
pub const ENDIAN_CONSTANT: u32 = 0x12345678;
pub const NO_INDEX: u32 = 0xffff_ffff;

/// Parsed DEX header (offsets/sizes for each section).
#[derive(Debug, Clone)]
pub struct DexHeader {
    pub version: u32,
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
    /// Set when this DEX is part of a single-file container (Android 14+ 041).
    pub container_off: usize,
}

impl DexHeader {
    /// Parse a DEX header that begins at `base` inside `r`'s buffer.
    pub fn parse(r: &mut Reader, base: usize) -> Result<DexHeader> {
        r.set_pos(base);
        let magic = r.array8()?;
        if &magic[0..4] != DEX_MAGIC.as_slice() {
            return Err(DexError::BadMagic(magic));
        }
        // magic[4..7] = version digits, magic[7] = 0
        let version = parse_version(&magic)?;
        let checksum = r.u32()?;
        let mut signature = [0u8; 20];
        signature.copy_from_slice(r.bytes(20)?);
        let file_size = r.u32()?;
        let header_size = r.u32()?;
        let endian_tag = r.u32()?;
        let link_size = r.u32()?;
        let link_off = r.u32()?;
        let map_off = r.u32()?;
        let string_ids_size = r.u32()?;
        let string_ids_off = r.u32()?;
        let type_ids_size = r.u32()?;
        let type_ids_off = r.u32()?;
        let proto_ids_size = r.u32()?;
        let proto_ids_off = r.u32()?;
        let field_ids_size = r.u32()?;
        let field_ids_off = r.u32()?;
        let method_ids_size = r.u32()?;
        let method_ids_off = r.u32()?;
        let class_defs_size = r.u32()?;
        let class_defs_off = r.u32()?;
        let data_size = r.u32()?;
        let data_off = r.u32()?;

        Ok(DexHeader {
            version,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
            container_off: base,
        })
    }
}

fn parse_version(magic: &[u8; 8]) -> Result<u32> {
    // magic = "dex\n" + 3 ascii digits + 0x00
    let digits = &magic[4..7];
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return Err(DexError::BadMagic(*magic));
    }
    let v = (digits[0] - b'0') as u32 * 100
        + (digits[1] - b'0') as u32 * 10
        + (digits[2] - b'0') as u32;
    // Accept the historical range 035..=041 (041 = container format).
    if !(35..=41).contains(&v) {
        return Err(DexError::UnsupportedVersion(v));
    }
    Ok(v)
}

/// Find the byte offsets of every `dex\n0XX\0` header in a buffer.
///
/// Classic multi-dex ships separate `classes*.dex` files (one header each), but
/// the Android 14+ container format packs several DEX images into one file. This
/// scan supports both: callers parse one `DexFile` per returned offset.
pub fn find_dex_headers(data: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut i = 0;
    while i + 8 <= data.len() {
        if &data[i..i + 4] == DEX_MAGIC.as_slice()
            && data[i + 4].is_ascii_digit()
            && data[i + 5].is_ascii_digit()
            && data[i + 6].is_ascii_digit()
            && data[i + 7] == 0
        {
            offsets.push(i);
            // Skip ahead conservatively; headers are aligned but contents vary.
            i += 4;
        } else {
            i += 1;
        }
    }
    if offsets.is_empty() {
        offsets.push(0);
    }
    offsets
}
