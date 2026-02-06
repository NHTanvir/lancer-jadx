//! JVM `.class` file reader (constant pool, fields, methods) + Java rendering.
//!
//! The native JVM-bytecode path recovers the class/field/method *structure* and
//! signatures; method bodies are emitted as stubs (upstream jadx defers full
//! JVM-bytecode decompilation to a pluggable backend — see
//! `--plugin-decompiler`). The DEX path is the primary, full decompiler.

use crate::args::JadxArgs;
use byteorder::{BigEndian, ReadBytesExt};
use jadx_dex::access::{self, AccessKind};
use jadx_dex::descriptor::descriptor_to_java;
use std::io::{Cursor, Read};

const MAGIC: u32 = 0xCAFE_BABE;

#[derive(Debug, Clone)]
enum Const {
    Utf8(String),
    Class(u16),
    Other,
}

#[derive(Debug, Clone)]
pub struct JvmMember {
    pub access_flags: u32,
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone)]
pub struct JvmClass {
    pub access_flags: u32,
    pub name: String,
    pub super_name: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<JvmMember>,
    pub methods: Vec<JvmMember>,
}

impl JvmClass {
    pub fn package(&self) -> String {
        jadx_dex::descriptor::package_of(&self.name)
    }
    pub fn simple_name(&self) -> String {
        jadx_dex::descriptor::simple_name(&self.name)
    }

    pub fn parse(bytes: &[u8]) -> anyhow::Result<JvmClass> {
        let mut c = Cursor::new(bytes);
        let magic = c.read_u32::<BigEndian>()?;
        if magic != MAGIC {
            anyhow::bail!("not a JVM class file (bad magic 0x{magic:08x})");
        }
        let _minor = c.read_u16::<BigEndian>()?;
        let _major = c.read_u16::<BigEndian>()?;
        let cp_count = c.read_u16::<BigEndian>()?;

        let mut pool: Vec<Const> = vec![Const::Other; cp_count as usize];
        let mut i = 1usize;
        while i < cp_count as usize {
            let tag = c.read_u8()?;
            match tag {
                1 => {
                    let len = c.read_u16::<BigEndian>()? as usize;
                    let mut buf = vec![0u8; len];
                    c.read_exact(&mut buf)?;
                    pool[i] = Const::Utf8(decode_jvm_utf8(&buf));
                }
                7 => {
                    let name_idx = c.read_u16::<BigEndian>()?;
                    pool[i] = Const::Class(name_idx);
                }
                8 | 16 | 19 | 20 => {
                    let _ = c.read_u16::<BigEndian>()?;
                }
                15 => {
                    let _ = c.read_u8()?;
                    let _ = c.read_u16::<BigEndian>()?;
                }
                3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => {
                    let _ = c.read_u32::<BigEndian>()?;
                }
                5 | 6 => {
                    let _ = c.read_u32::<BigEndian>()?;
                    let _ = c.read_u32::<BigEndian>()?;
                    i += 1; // long/double occupy two pool slots
                }
                _ => anyhow::bail!("unknown constant pool tag {tag}"),
            }
            i += 1;
        }

        let resolve_class = |idx: u16| -> Option<String> {
            match pool.get(idx as usize) {
                Some(Const::Class(name_idx)) => match pool.get(*name_idx as usize) {
                    Some(Const::Utf8(s)) => Some(s.replace('/', ".")),
                    _ => None,
                },
                _ => None,
            }
        };
        let resolve_utf8 = |idx: u16| -> String {
            match pool.get(idx as usize) {
                Some(Const::Utf8(s)) => s.clone(),
                _ => String::new(),
            }
        };

        let access_flags = c.read_u16::<BigEndian>()? as u32;
        let this_class = c.read_u16::<BigEndian>()?;
        let super_class = c.read_u16::<BigEndian>()?;
        let name = resolve_class(this_class).unwrap_or_default();
        let super_name = if super_class == 0 {
            None
        } else {
            resolve_class(super_class)
        };

        let iface_count = c.read_u16::<BigEndian>()?;
        let mut interfaces = Vec::new();
        for _ in 0..iface_count {
            let idx = c.read_u16::<BigEndian>()?;
            if let Some(n) = resolve_class(idx) {
                interfaces.push(n);
            }
        }

        let fields = read_members(&mut c, &resolve_utf8)?;
        let methods = read_members(&mut c, &resolve_utf8)?;

        Ok(JvmClass {
            access_flags,
            name,
            super_name,
            interfaces,
            fields,
            methods,
        })
    }

    /// Render Java source for this class (structure + signatures + stub bodies).
    pub fn to_java(&self, _args: &JadxArgs) -> String {
        let mut out = String::new();
        let pkg = self.package();
        if !pkg.is_empty() {
            out.push_str(&format!("package {pkg};\n\n"));
        }
        let modifiers = access::modifiers(self.access_flags, AccessKind::Class);
        let keyword = access::class_keyword(self.access_flags);
        out.push_str(&modifiers);
        if !modifiers.is_empty() {
            out.push(' ');
        }
        out.push_str(&format!("{keyword} {}", self.simple_name()));
        if let Some(s) = &self.super_name {
            if s != "java.lang.Object" {
                out.push_str(&format!(" extends {s}"));
            }
        }
        if !self.interfaces.is_empty() {
            let kw = if access::is_interface(self.access_flags) {
                "extends"
            } else {
                "implements"
            };
            out.push_str(&format!(" {kw} {}", self.interfaces.join(", ")));
        }
        out.push_str(" {\n");

        for f in &self.fields {
            let m = access::modifiers(f.access_flags, AccessKind::Field);
            let ty = descriptor_to_java(&f.descriptor);
            out.push_str("    ");
            if !m.is_empty() {
                out.push_str(&m);
                out.push(' ');
            }
            out.push_str(&format!("{ty} {};\n", f.name));
        }
        if !self.fields.is_empty() {
            out.push('\n');
        }

        for me in &self.methods {
            let m = access::modifiers(me.access_flags, AccessKind::Method);
            let (ret, params) = parse_method_descriptor(&me.descriptor);
            let mut param_list: Vec<String> = Vec::new();
            for (i, p) in params.iter().enumerate() {
                param_list.push(format!("{p} p{i}"));
            }
            out.push_str("    ");
            if !m.is_empty() {
                out.push_str(&m);
                out.push(' ');
            }
            let display_name = if me.name == "<init>" {
                self.simple_name()
            } else {
                me.name.clone()
            };
            if me.name != "<init>" && me.name != "<clinit>" {
                out.push_str(&format!("{ret} "));
            }
            out.push_str(&format!("{display_name}({})", param_list.join(", ")));
            if access::is_abstract(me.access_flags) || access::is_native(me.access_flags) {
                out.push_str(";\n");
            } else {
                out.push_str(" {\n");
                out.push_str("        // JVM bytecode body (native structural decode; use --plugin-decompiler for full source)\n");
                if ret != "void" && me.name != "<init>" && me.name != "<clinit>" {
                    out.push_str(&format!("        return {};\n", default_value(&ret)));
                }
                out.push_str("    }\n");
            }
        }

        out.push_str("}\n");
        out
    }
}

fn read_members<F: Fn(u16) -> String>(
    c: &mut Cursor<&[u8]>,
    resolve_utf8: &F,
) -> anyhow::Result<Vec<JvmMember>> {
    let count = c.read_u16::<BigEndian>()?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let access_flags = c.read_u16::<BigEndian>()? as u32;
        let name_idx = c.read_u16::<BigEndian>()?;
        let desc_idx = c.read_u16::<BigEndian>()?;
        let attr_count = c.read_u16::<BigEndian>()?;
        for _ in 0..attr_count {
            let _name = c.read_u16::<BigEndian>()?;
            let len = c.read_u32::<BigEndian>()?;
            let mut skip = vec![0u8; len as usize];
            c.read_exact(&mut skip)?;
        }
        out.push(JvmMember {
            access_flags,
            name: resolve_utf8(name_idx),
            descriptor: resolve_utf8(desc_idx),
        });
    }
    Ok(out)
}

/// Parse a method descriptor `(II)Ljava/lang/String;` → (return, params).
pub fn parse_method_descriptor(desc: &str) -> (String, Vec<String>) {
    let bytes = desc.as_bytes();
    let mut params = Vec::new();
    let mut i = 0;
    if i < bytes.len() && bytes[i] == b'(' {
        i += 1;
    }
    while i < bytes.len() && bytes[i] != b')' {
        let (ty, next) = read_one_type(desc, i);
        params.push(ty);
        i = next;
    }
    if i < bytes.len() && bytes[i] == b')' {
        i += 1;
    }
    let ret = if i < bytes.len() {
        let (ty, _) = read_one_type(desc, i);
        ty
    } else {
        "void".to_string()
    };
    (ret, params)
}

fn read_one_type(desc: &str, start: usize) -> (String, usize) {
    let bytes = desc.as_bytes();
    let mut i = start;
    while i < bytes.len() && bytes[i] == b'[' {
        i += 1;
    }
    if i >= bytes.len() {
        return ("Object".to_string(), i);
    }
    let end = match bytes[i] {
        b'L' => {
            let mut j = i;
            while j < bytes.len() && bytes[j] != b';' {
                j += 1;
            }
            j + 1
        }
        _ => i + 1,
    };
    let slice = &desc[start..end.min(desc.len())];
    (descriptor_to_java(slice), end)
}

fn default_value(ty: &str) -> &'static str {
    match ty {
        "boolean" => "false",
        "byte" | "short" | "int" | "long" | "char" => "0",
        "float" | "double" => "0",
        _ => "null",
    }
}

fn decode_jvm_utf8(bytes: &[u8]) -> String {
    // JVM modified UTF-8 ≈ DEX MUTF-8 for our purposes.
    jadx_dex::reader::decode_mutf8(bytes).unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}
