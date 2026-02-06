//! The parsed DEX file model: pools, class definitions, and resolution helpers.

use crate::access;
use crate::code::CodeItem;
use crate::descriptor::descriptor_to_java;
use crate::error::{DexError, Result};
use crate::header::{DexHeader, NO_INDEX};
use crate::reader::Reader;

#[derive(Debug, Clone)]
pub struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub params: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Debug, Clone)]
pub struct DexFieldEntry {
    pub field_idx: u32,
    pub access_flags: u32,
}

#[derive(Debug, Clone)]
pub struct DexMethodEntry {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code: Option<CodeItem>,
}

#[derive(Debug, Clone)]
pub struct DexClass {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces: Vec<u16>,
    pub source_file_idx: u32,
    pub static_fields: Vec<DexFieldEntry>,
    pub instance_fields: Vec<DexFieldEntry>,
    pub direct_methods: Vec<DexMethodEntry>,
    pub virtual_methods: Vec<DexMethodEntry>,
}

/// A fully resolved method reference (class/name/signature in Java terms).
#[derive(Debug, Clone)]
pub struct MethodRef {
    pub class: String,
    pub name: String,
    pub return_type: String,
    pub params: Vec<String>,
}

/// A fully resolved field reference.
#[derive(Debug, Clone)]
pub struct FieldRef {
    pub class: String,
    pub name: String,
    pub field_type: String,
}

#[derive(Debug, Clone)]
pub struct DexFile {
    pub header: DexHeader,
    pub strings: Vec<String>,
    pub type_ids: Vec<u32>,
    pub protos: Vec<ProtoId>,
    pub field_ids: Vec<FieldId>,
    pub method_ids: Vec<MethodId>,
    pub classes: Vec<DexClass>,
}

impl DexFile {
    /// Parse a DEX whose header starts at `base` inside `data`.
    pub fn parse(data: &[u8], base: usize) -> Result<DexFile> {
        let mut r = Reader::new(data);
        let header = DexHeader::parse(&mut r, base)?;

        // --- strings ---
        let mut strings = Vec::with_capacity(header.string_ids_size as usize);
        for i in 0..header.string_ids_size as usize {
            r.set_pos(header.string_ids_off as usize + i * 4);
            let data_off = r.u32()? as usize;
            r.set_pos(data_off);
            let utf16_len = r.uleb128()? as usize;
            strings.push(r.mutf8(utf16_len)?);
        }

        // --- type ids ---
        let mut type_ids = Vec::with_capacity(header.type_ids_size as usize);
        r.set_pos(header.type_ids_off as usize);
        for _ in 0..header.type_ids_size {
            type_ids.push(r.u32()?);
        }

        // --- proto ids ---
        let mut protos = Vec::with_capacity(header.proto_ids_size as usize);
        for i in 0..header.proto_ids_size as usize {
            r.set_pos(header.proto_ids_off as usize + i * 12);
            let shorty_idx = r.u32()?;
            let return_type_idx = r.u32()?;
            let parameters_off = r.u32()?;
            let params = if parameters_off != 0 {
                parse_type_list(&mut r, parameters_off as usize)?
            } else {
                Vec::new()
            };
            protos.push(ProtoId {
                shorty_idx,
                return_type_idx,
                params,
            });
        }

        // --- field ids ---
        let mut field_ids = Vec::with_capacity(header.field_ids_size as usize);
        r.set_pos(header.field_ids_off as usize);
        for _ in 0..header.field_ids_size {
            let class_idx = r.u16()?;
            let type_idx = r.u16()?;
            let name_idx = r.u32()?;
            field_ids.push(FieldId {
                class_idx,
                type_idx,
                name_idx,
            });
        }

        // --- method ids ---
        let mut method_ids = Vec::with_capacity(header.method_ids_size as usize);
        r.set_pos(header.method_ids_off as usize);
        for _ in 0..header.method_ids_size {
            let class_idx = r.u16()?;
            let proto_idx = r.u16()?;
            let name_idx = r.u32()?;
            method_ids.push(MethodId {
                class_idx,
                proto_idx,
                name_idx,
            });
        }

        // --- class defs ---
        let mut classes = Vec::with_capacity(header.class_defs_size as usize);
        for i in 0..header.class_defs_size as usize {
            r.set_pos(header.class_defs_off as usize + i * 32);
            let class_idx = r.u32()?;
            let access_flags = r.u32()?;
            let superclass_idx = r.u32()?;
            let interfaces_off = r.u32()?;
            let source_file_idx = r.u32()?;
            let _annotations_off = r.u32()?;
            let class_data_off = r.u32()?;
            let _static_values_off = r.u32()?;

            let interfaces = if interfaces_off != 0 {
                parse_type_list(&mut r, interfaces_off as usize)?
            } else {
                Vec::new()
            };

            let (static_fields, instance_fields, direct_methods, virtual_methods) =
                if class_data_off != 0 {
                    parse_class_data(&mut r, class_data_off as usize, data, &strings)?
                } else {
                    (Vec::new(), Vec::new(), Vec::new(), Vec::new())
                };

            classes.push(DexClass {
                class_idx,
                access_flags,
                superclass_idx,
                interfaces,
                source_file_idx,
                static_fields,
                instance_fields,
                direct_methods,
                virtual_methods,
            });
        }

        Ok(DexFile {
            header,
            strings,
            type_ids,
            protos,
            field_ids,
            method_ids,
            classes,
        })
    }

    pub fn string(&self, idx: u32) -> &str {
        self.strings.get(idx as usize).map(|s| s.as_str()).unwrap_or("")
    }

    pub fn type_descriptor(&self, type_idx: u32) -> &str {
        match self.type_ids.get(type_idx as usize) {
            Some(&s) => self.string(s),
            None => "",
        }
    }

    pub fn type_name(&self, type_idx: u32) -> String {
        if type_idx == NO_INDEX {
            return "void".to_string();
        }
        descriptor_to_java(self.type_descriptor(type_idx))
    }

    pub fn class_name(&self, class: &DexClass) -> String {
        descriptor_to_java(self.type_descriptor(class.class_idx))
    }

    pub fn superclass_name(&self, class: &DexClass) -> Option<String> {
        if class.superclass_idx == NO_INDEX {
            None
        } else {
            Some(self.type_name(class.superclass_idx))
        }
    }

    pub fn interface_names(&self, class: &DexClass) -> Vec<String> {
        class
            .interfaces
            .iter()
            .map(|&t| self.type_name(t as u32))
            .collect()
    }

    pub fn source_file(&self, class: &DexClass) -> Option<&str> {
        if class.source_file_idx == NO_INDEX {
            None
        } else {
            Some(self.string(class.source_file_idx))
        }
    }

    pub fn proto(&self, proto_idx: u32) -> Option<&ProtoId> {
        self.protos.get(proto_idx as usize)
    }

    pub fn proto_return(&self, proto_idx: u32) -> String {
        match self.proto(proto_idx) {
            Some(p) => self.type_name(p.return_type_idx),
            None => "void".to_string(),
        }
    }

    pub fn proto_params(&self, proto_idx: u32) -> Vec<String> {
        match self.proto(proto_idx) {
            Some(p) => p.params.iter().map(|&t| self.type_name(t as u32)).collect(),
            None => Vec::new(),
        }
    }

    pub fn field_ref(&self, field_idx: u32) -> FieldRef {
        match self.field_ids.get(field_idx as usize) {
            Some(f) => FieldRef {
                class: self.type_name(f.class_idx as u32),
                name: self.string(f.name_idx).to_string(),
                field_type: self.type_name(f.type_idx as u32),
            },
            None => FieldRef {
                class: String::new(),
                name: format!("field@{field_idx}"),
                field_type: "Object".to_string(),
            },
        }
    }

    pub fn method_ref(&self, method_idx: u32) -> MethodRef {
        match self.method_ids.get(method_idx as usize) {
            Some(m) => MethodRef {
                class: self.type_name(m.class_idx as u32),
                name: self.string(m.name_idx).to_string(),
                return_type: self.proto_return(m.proto_idx as u32),
                params: self.proto_params(m.proto_idx as u32),
            },
            None => MethodRef {
                class: String::new(),
                name: format!("method@{method_idx}"),
                return_type: "void".to_string(),
                params: Vec::new(),
            },
        }
    }

    pub fn field_entry_ref(&self, e: &DexFieldEntry) -> FieldRef {
        self.field_ref(e.field_idx)
    }

    pub fn method_entry_ref(&self, e: &DexMethodEntry) -> MethodRef {
        self.method_ref(e.method_idx)
    }

    /// Resolve debug info (line numbers + param names) for a method's code item,
    /// if present. Returns a clone of the code with `debug` filled in.
    pub fn resolve_debug(&self, code: &CodeItem) -> Option<crate::code::DebugInfo> {
        if code.debug_info_off == 0 {
            return None;
        }
        // We need the original buffer; debug parse is done eagerly during parse
        // when the buffer is available. Here we just surface what was attached.
        code.debug.clone()
    }
}

fn parse_type_list(r: &mut Reader, off: usize) -> Result<Vec<u16>> {
    r.set_pos(off);
    let size = r.u32()? as usize;
    let mut out = Vec::with_capacity(size);
    for _ in 0..size {
        out.push(r.u16()?);
    }
    Ok(out)
}

#[allow(clippy::type_complexity)]
fn parse_class_data(
    r: &mut Reader,
    off: usize,
    data: &[u8],
    strings: &[String],
) -> Result<(
    Vec<DexFieldEntry>,
    Vec<DexFieldEntry>,
    Vec<DexMethodEntry>,
    Vec<DexMethodEntry>,
)> {
    r.set_pos(off);
    let static_fields_size = r.uleb128()? as usize;
    let instance_fields_size = r.uleb128()? as usize;
    let direct_methods_size = r.uleb128()? as usize;
    let virtual_methods_size = r.uleb128()? as usize;

    let static_fields = parse_fields(r, static_fields_size)?;
    let instance_fields = parse_fields(r, instance_fields_size)?;
    let direct_methods = parse_methods(r, direct_methods_size, data, strings)?;
    let virtual_methods = parse_methods(r, virtual_methods_size, data, strings)?;

    Ok((
        static_fields,
        instance_fields,
        direct_methods,
        virtual_methods,
    ))
}

fn parse_fields(r: &mut Reader, count: usize) -> Result<Vec<DexFieldEntry>> {
    let mut out = Vec::with_capacity(count);
    let mut field_idx: u32 = 0;
    for _ in 0..count {
        let diff = r.uleb128()?;
        field_idx = field_idx.checked_add(diff).ok_or_else(|| {
            DexError::Malformed("field index delta overflow".to_string())
        })?;
        let access_flags = r.uleb128()?;
        out.push(DexFieldEntry {
            field_idx,
            access_flags,
        });
    }
    Ok(out)
}

fn parse_methods(
    r: &mut Reader,
    count: usize,
    data: &[u8],
    strings: &[String],
) -> Result<Vec<DexMethodEntry>> {
    let mut out = Vec::with_capacity(count);
    let mut method_idx: u32 = 0;
    for _ in 0..count {
        let diff = r.uleb128()?;
        method_idx = method_idx.checked_add(diff).ok_or_else(|| {
            DexError::Malformed("method index delta overflow".to_string())
        })?;
        let access_flags = r.uleb128()?;
        let code_off = r.uleb128()? as usize;
        let saved = r.pos();
        let code = if code_off != 0 {
            let mut cr = Reader::new(data);
            let mut ci = CodeItem::parse(&mut cr, code_off)?;
            if ci.debug_info_off != 0 {
                let mut dr = Reader::new(data);
                if let Ok(dbg) =
                    crate::code::parse_debug_info(&mut dr, ci.debug_info_off as usize, strings)
                {
                    ci.debug = Some(dbg);
                }
            }
            Some(ci)
        } else {
            None
        };
        r.set_pos(saved);
        out.push(DexMethodEntry {
            method_idx,
            access_flags,
            code,
        });
    }
    Ok(out)
}

/// Convenience: is this method a constructor (`<init>`/`<clinit>`)?
pub fn is_init_method(name: &str) -> bool {
    name == "<init>" || name == "<clinit>"
}

/// Re-export commonly used access helpers.
pub use access::{class_keyword, modifiers, AccessKind};
