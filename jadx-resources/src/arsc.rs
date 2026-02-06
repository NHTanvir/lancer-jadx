//! `resources.arsc` decoder: package/type/entry tables → resolved resources.

use crate::error::{ResError, Result};
use crate::pool::{StringPool, RES_STRING_POOL_TYPE};
use crate::reader::{Buf, ChunkHeader};
use crate::value;
use std::collections::BTreeMap;

const RES_TABLE_TYPE: u16 = 0x0002;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;

const FLAG_COMPLEX: u16 = 0x0001;
const FLAG_SPARSE: u8 = 0x01;
const FLAG_OFFSET16: u8 = 0x02;
const NO_ENTRY: u32 = 0xffff_ffff;
const MAX_ENTRIES: usize = 1 << 20;

#[derive(Debug, Clone)]
pub struct ResEntry {
    pub id: u32,
    pub package: String,
    pub type_name: String,
    pub name: String,
    pub value: String,
    pub is_string: bool,
}

impl ResEntry {
    /// The `R.type.name` reference form.
    pub fn r_name(&self) -> String {
        format!("R.{}.{}", self.type_name, self.name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Arsc {
    pub global_strings: StringPool,
    pub entries: BTreeMap<u32, ResEntry>,
}

impl Arsc {
    pub fn resolve(&self, id: u32) -> Option<&ResEntry> {
        self.entries.get(&id)
    }

    /// All entries of a given resource type (e.g. `"string"`).
    pub fn of_type<'a>(&'a self, type_name: &'a str) -> impl Iterator<Item = &'a ResEntry> + 'a {
        self.entries.values().filter(move |e| e.type_name == type_name)
    }

    /// Decode a `resources.arsc` buffer.
    pub fn parse(data: &[u8]) -> Result<Arsc> {
        let mut b = Buf::new(data);
        let table = ChunkHeader::read(&mut b)?;
        if table.type_id != RES_TABLE_TYPE {
            return Err(ResError::BadChunk {
                expected: RES_TABLE_TYPE,
                found: table.type_id,
                offset: 0,
            });
        }
        let _package_count = b.u32()?;

        let mut arsc = Arsc::default();
        let mut pos = table.start + table.header_size as usize;
        while pos + 8 <= data.len() && pos < table.end() {
            let mut cb = Buf::at(data, pos);
            let ch = ChunkHeader::read(&mut cb)?;
            if ch.chunk_size == 0 {
                break;
            }
            match ch.type_id {
                RES_STRING_POOL_TYPE => {
                    arsc.global_strings = StringPool::parse(data, ch.start)?;
                }
                RES_TABLE_PACKAGE_TYPE => {
                    parse_package(data, &ch, &arsc.global_strings, &mut arsc.entries)?;
                }
                _ => {}
            }
            pos = ch.end().max(pos + 8);
        }
        Ok(arsc)
    }
}

fn parse_package(
    data: &[u8],
    pkg: &ChunkHeader,
    global_strings: &StringPool,
    entries: &mut BTreeMap<u32, ResEntry>,
) -> Result<()> {
    let mut b = Buf::at(data, pkg.start + 8);
    let pkg_id = b.u32()?;
    let pkg_name = read_package_name(data, b.pos);
    b.seek(pkg.start + 8 + 4 + 256);
    let type_strings_off = b.u32()? as usize;
    let _last_public_type = b.u32()?;
    let key_strings_off = b.u32()? as usize;
    let _last_public_key = b.u32()?;

    let type_strings = if type_strings_off != 0 {
        StringPool::parse(data, pkg.start + type_strings_off).unwrap_or_default()
    } else {
        StringPool::default()
    };
    let key_strings = if key_strings_off != 0 {
        StringPool::parse(data, pkg.start + key_strings_off).unwrap_or_default()
    } else {
        StringPool::default()
    };

    let mut pos = pkg.start + pkg.header_size as usize;
    while pos + 8 <= data.len() && pos < pkg.end() {
        let mut cb = Buf::at(data, pos);
        let ch = ChunkHeader::read(&mut cb)?;
        if ch.chunk_size == 0 {
            break;
        }
        match ch.type_id {
            RES_TABLE_TYPE_SPEC_TYPE => { /* per-type config flags — not needed */ }
            RES_TABLE_TYPE_TYPE => {
                let _ = parse_type(
                    data,
                    &ch,
                    pkg_id,
                    &pkg_name,
                    &type_strings,
                    &key_strings,
                    global_strings,
                    entries,
                );
            }
            _ => {}
        }
        pos = ch.end().max(pos + 8);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_type(
    data: &[u8],
    ch: &ChunkHeader,
    pkg_id: u32,
    pkg_name: &str,
    type_strings: &StringPool,
    key_strings: &StringPool,
    global_strings: &StringPool,
    entries: &mut BTreeMap<u32, ResEntry>,
) -> Result<()> {
    let mut b = Buf::at(data, ch.start + 8);
    let type_id = b.u8()? as u32;
    let flags = b.u8()?;
    let _reserved = b.u16()?;
    let entry_count = (b.u32()? as usize).min(MAX_ENTRIES);
    let entries_start = b.u32()? as usize;

    let offsets_base = ch.start + ch.header_size as usize;
    let entries_base = ch.start + entries_start;

    // Read the entry-offset array.
    let mut offsets: Vec<(usize, Option<usize>)> = Vec::with_capacity(entry_count);
    if flags & FLAG_SPARSE != 0 {
        let mut ob = Buf::at(data, offsets_base);
        for _ in 0..entry_count {
            let v = ob.u32()?;
            let idx = (v & 0xffff) as usize;
            let off = ((v >> 16) * 4) as usize;
            offsets.push((idx, Some(off)));
        }
    } else if flags & FLAG_OFFSET16 != 0 {
        let mut ob = Buf::at(data, offsets_base);
        for i in 0..entry_count {
            let v = ob.u16()? as u32;
            let off = if v == 0xffff { None } else { Some((v * 4) as usize) };
            offsets.push((i, off));
        }
    } else {
        let mut ob = Buf::at(data, offsets_base);
        for i in 0..entry_count {
            let v = ob.u32()?;
            offsets.push((i, if v == NO_ENTRY { None } else { Some(v as usize) }));
        }
    }

    let type_name = type_strings.get_or(type_id.saturating_sub(1), "type");
    for (idx, off) in offsets {
        let off = match off {
            Some(o) => o,
            None => continue,
        };
        let entry_pos = entries_base + off;
        if let Some(entry) = parse_entry(data, entry_pos, key_strings, global_strings) {
            let id = (pkg_id << 24) | (type_id << 16) | idx as u32;
            entries.entry(id).or_insert(ResEntry {
                id,
                package: pkg_name.to_string(),
                type_name: type_name.clone(),
                name: entry.0,
                value: entry.1,
                is_string: entry.2,
            });
        }
    }
    Ok(())
}

fn parse_entry(
    data: &[u8],
    pos: usize,
    key_strings: &StringPool,
    global_strings: &StringPool,
) -> Option<(String, String, bool)> {
    let mut b = Buf::at(data, pos);
    let _size = b.u16().ok()?;
    let flags = b.u16().ok()?;
    let key = b.u32().ok()?;
    let name = key_strings.get_or(key, "entry");

    if flags & FLAG_COMPLEX != 0 {
        // map entry (style/array/attr/plurals) — value is structured.
        Some((name, "@complex".to_string(), false))
    } else {
        let _val_size = b.u16().ok()?;
        let _res0 = b.u8().ok()?;
        let data_type = b.u8().ok()?;
        let val_data = b.u32().ok()?;
        let value = value::format(data_type, val_data, global_strings);
        let is_string = data_type == value::TYPE_STRING;
        Some((name, value, is_string))
    }
}

fn read_package_name(data: &[u8], off: usize) -> String {
    let mut units = Vec::new();
    let mut p = off;
    for _ in 0..128 {
        if p + 1 >= data.len() {
            break;
        }
        let u = u16::from_le_bytes([data[p], data[p + 1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        p += 2;
    }
    String::from_utf16_lossy(&units)
}
