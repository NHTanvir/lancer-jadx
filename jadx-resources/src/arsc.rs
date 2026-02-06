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

// Well-known `Res_value` map names (`Res_value::name` field of a `ResTable_map`)
// used by attr/array/style/plurals bags. Values below 0x0100_0000 in these
// reserved ranges are framework attributes rather than ordinary references.
const ATTR_TYPE: u32 = 0x0100_0000;
const ATTR_MIN: u32 = 0x0100_0001;
const ATTR_MAX: u32 = 0x0100_0002;
const ATTR_L10N: u32 = 0x0100_0003;
const ATTR_OTHER: u32 = 0x0100_0004;
const ATTR_ZERO: u32 = 0x0100_0005;
const ATTR_ONE: u32 = 0x0100_0006;
const ATTR_TWO: u32 = 0x0100_0007;
const ATTR_FEW: u32 = 0x0100_0008;
const ATTR_MANY: u32 = 0x0100_0009;

#[derive(Debug, Clone)]
pub struct ResEntry {
    pub id: u32,
    pub package: String,
    pub type_name: String,
    pub name: String,
    pub value: String,
    pub is_string: bool,
    /// `true` when this entry is a complex (map/bag) entry: array, plurals,
    /// style or attr. For these `value` holds a rendered, readable form.
    pub is_complex: bool,
    /// `true` when the entry comes from the default configuration (no locale /
    /// density / orientation qualifiers). The canonical name→value resolution
    /// prefers a default-config entry over any qualified override.
    pub is_default_config: bool,
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
            RES_TABLE_TYPE_SPEC_TYPE => {
                // ResTable_typeSpec: header { type:u8, res0:u8, res1:u16,
                // entryCount:u32 } followed by entryCount * u32 config flags.
                // We don't need the flags; the chunk walker advances by
                // `ch.end()` below, so simply skipping keeps every package
                // byte-aligned for the following type chunks.
            }
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

    // ResTable_config follows the fixed header fields. Its leading u32 is the
    // structure size; the remaining bytes carry locale/density/orientation/etc.
    // For canonical resolution we only need to know whether this is the default
    // (all-zero) configuration, so we test the meaningful bytes for non-zero.
    let config_off = b.pos;
    let is_default = config_is_default(data, config_off);

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
        if let Some(parsed) = parse_entry(data, entry_pos, key_strings, global_strings) {
            let id = (pkg_id << 24) | (type_id << 16) | idx as u32;
            let candidate = ResEntry {
                id,
                package: pkg_name.to_string(),
                type_name: type_name.clone(),
                name: parsed.name,
                value: parsed.value,
                is_string: parsed.is_string,
                is_complex: parsed.is_complex,
                is_default_config: is_default,
            };
            match entries.get(&id) {
                // Prefer the default configuration: only replace a previously
                // stored non-default entry when this one is the default config.
                Some(existing) if existing.is_default_config => {}
                Some(_) if !is_default => {}
                _ => {
                    entries.insert(id, candidate);
                }
            }
        }
    }
    Ok(())
}

/// Decode just enough of a `ResTable_config` at `off` to tell whether it is the
/// default (all-qualifier-zero) configuration. The first u32 is the struct
/// size; if every byte after it (up to that size) is zero the config carries no
/// locale/density/orientation/etc. qualifier and is the base variant.
fn config_is_default(data: &[u8], off: usize) -> bool {
    if off + 4 > data.len() {
        return true;
    }
    let size = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]) as usize;
    // A size of just the leading word (or a degenerate/truncated size) has no
    // qualifier bytes and is therefore the default configuration.
    if size <= 4 {
        return true;
    }
    let end = (off + size).min(data.len());
    data[off + 4..end].iter().all(|&byte| byte == 0)
}

/// Result of decoding a single resource entry record.
struct ParsedEntry {
    name: String,
    value: String,
    is_string: bool,
    is_complex: bool,
}

fn parse_entry(
    data: &[u8],
    pos: usize,
    key_strings: &StringPool,
    global_strings: &StringPool,
) -> Option<ParsedEntry> {
    let mut b = Buf::at(data, pos);
    let _size = b.u16().ok()?;
    let flags = b.u16().ok()?;
    let key = b.u32().ok()?;
    let name = key_strings.get_or(key, "entry");

    if flags & FLAG_COMPLEX != 0 {
        // ResTable_map_entry: after the common header (size/flags/key) come a
        // ResTable_ref `parent` and a u32 `count`, then `count` ResTable_map
        // records { name:u32, value:Res_value(8 bytes) }.
        let parent = b.u32().ok()?;
        let count = (b.u32().ok()? as usize).min(MAX_ENTRIES);
        let value = render_complex(&mut b, parent, count, global_strings);
        Some(ParsedEntry {
            name,
            value,
            is_string: false,
            is_complex: true,
        })
    } else {
        let _val_size = b.u16().ok()?;
        let _res0 = b.u8().ok()?;
        let data_type = b.u8().ok()?;
        let val_data = b.u32().ok()?;
        let value = value::format(data_type, val_data, global_strings);
        let is_string = data_type == value::TYPE_STRING;
        Some(ParsedEntry {
            name,
            value,
            is_string,
            is_complex: false,
        })
    }
}

/// Render the children of a complex (map/bag) entry into a readable string.
///
/// Arrays/plurals (children whose `name` is a framework array/plurals item or a
/// plain index) become `[v1, v2, ...]`; styles/attrs (children keyed by an attr
/// reference) become `{0x...=value, ...}`. Children are formatted via the shared
/// `Res_value` formatter so references/dimensions/colors stay consistent with
/// simple entries.
fn render_complex(b: &mut Buf, _parent: u32, count: usize, global_strings: &StringPool) -> String {
    let mut items: Vec<String> = Vec::with_capacity(count);
    let mut keyed: Vec<(String, String)> = Vec::with_capacity(count);
    let mut is_bag = false;

    for _ in 0..count {
        let name_ref = match b.u32() {
            Ok(v) => v,
            Err(_) => break,
        };
        // Res_value: size:u16, res0:u8, dataType:u8, data:u32.
        let _val_size = b.u16().unwrap_or(0);
        let _res0 = b.u8().unwrap_or(0);
        let data_type = b.u8().unwrap_or(value::TYPE_NULL);
        let data = match b.u32() {
            Ok(v) => v,
            Err(_) => break,
        };
        let rendered = value::format(data_type, data, global_strings);

        match map_name_label(name_ref) {
            // Positional / array / plurals item: collect as an ordered element.
            None => items.push(rendered),
            // Named style / attr child: collect as a key=value pair.
            Some(label) => {
                is_bag = true;
                keyed.push((label, rendered));
            }
        }
    }

    if is_bag {
        let body = keyed
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{{{body}}}")
    } else {
        format!("[{}]", items.join(", "))
    }
}

/// Map a `ResTable_map::name` to a human label, or `None` when the child is an
/// array/plurals element that should render positionally.
///
/// Plain attribute references (`pkg/type/entry` ids, i.e. high byte non-zero)
/// and framework attr-meta names denote a style/attr bag and yield a label.
/// The framework array/plurals item markers and bare indices return `None`.
fn map_name_label(name: u32) -> Option<String> {
    match name {
        // android.R.attr meta keys used inside <attr> declarations.
        ATTR_TYPE => Some("type".to_string()),
        ATTR_MIN => Some("min".to_string()),
        ATTR_MAX => Some("max".to_string()),
        ATTR_L10N => Some("l10n".to_string()),
        ATTR_OTHER => Some("other".to_string()),
        // Plurals quantity keys.
        ATTR_ZERO => Some("zero".to_string()),
        ATTR_ONE => Some("one".to_string()),
        ATTR_TWO => Some("two".to_string()),
        ATTR_FEW => Some("few".to_string()),
        ATTR_MANY => Some("many".to_string()),
        // The array item sentinel (android.R.attr first array entry) and bare
        // positional indices render as ordered elements.
        0 | 0x0100_0000..=0x0100_ffff => None,
        // A real resource reference (own package or framework attr id) keys a
        // style/attr bag child.
        n if n >> 24 != 0 => Some(format!("@0x{n:08x}")),
        // Anything else (small positional index) is an array element.
        _ => None,
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
