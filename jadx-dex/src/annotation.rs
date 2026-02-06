//! DEX `encoded_value` / `encoded_annotation` decoding (Dalvik spec).
//!
//! Annotations and the `dalvik.annotation.Signature` carrier (which holds the
//! Java generic signatures erased from the descriptor pools) are stored as
//! `annotations_directory_item`s referenced from each `class_def`. This module
//! decodes the `encoded_value` grammar and resolves string/type/field/method
//! indices into Java-dotted names so the code generators can re-emit them.

use crate::descriptor::descriptor_to_java;
use crate::error::Result;
use crate::reader::Reader;
use std::fmt;

// value_type tags (low 5 bits of the value byte).
const VALUE_BYTE: u8 = 0x00;
const VALUE_SHORT: u8 = 0x02;
const VALUE_CHAR: u8 = 0x03;
const VALUE_INT: u8 = 0x04;
const VALUE_LONG: u8 = 0x06;
const VALUE_FLOAT: u8 = 0x10;
const VALUE_DOUBLE: u8 = 0x11;
const VALUE_METHOD_TYPE: u8 = 0x15;
const VALUE_METHOD_HANDLE: u8 = 0x16;
const VALUE_STRING: u8 = 0x17;
const VALUE_TYPE: u8 = 0x18;
const VALUE_FIELD: u8 = 0x19;
const VALUE_METHOD: u8 = 0x1a;
const VALUE_ENUM: u8 = 0x1b;
const VALUE_ARRAY: u8 = 0x1c;
const VALUE_ANNOTATION: u8 = 0x1d;
const VALUE_NULL: u8 = 0x1e;
const VALUE_BOOLEAN: u8 = 0x1f;

/// A decoded `encoded_value`.
#[derive(Debug, Clone)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    /// proto index of a `MethodType`.
    MethodType(u32),
    /// method-handle index.
    MethodHandle(u32),
    String(String),
    /// A `Class` literal (Java-dotted type name).
    Type(String),
    /// A field reference (`Class.name`).
    Field(String),
    /// A method reference (`Class.name`).
    Method(String),
    /// An enum constant (`Class.NAME`).
    Enum(String),
    Array(Vec<EncodedValue>),
    Annotation(Annotation),
    Null,
    Boolean(bool),
}

/// A decoded `encoded_annotation`.
#[derive(Debug, Clone)]
pub struct Annotation {
    /// Annotation type as a Java-dotted name (e.g. `java.lang.Override`).
    pub type_name: String,
    /// Name/value element pairs in declaration order.
    pub elements: Vec<(String, EncodedValue)>,
}

impl Annotation {
    /// True if this is a system / synthetic annotation that should not be
    /// re-emitted as source (`dalvik.annotation.*`, the JSR-175 meta types, and
    /// the synthetic markers jadx hides).
    pub fn is_system(&self) -> bool {
        let t = &self.type_name;
        t.starts_with("dalvik.annotation.")
            || t.starts_with("java.lang.annotation.")
            || t == "java.lang.Synthetic"
            || t == "dalvik.annotation.Synthetic"
    }
}

/// Read the pools needed to resolve an `encoded_value`. Holds borrows of the
/// already-built `DexFile` pools so decoding does not require `&DexFile` (which
/// would conflict with the mutable second pass that fills annotation fields).
pub struct Resolver<'a> {
    pub strings: &'a [String],
    pub type_ids: &'a [u32],
    pub field_ids: &'a [crate::dexfile::FieldId],
    pub method_ids: &'a [crate::dexfile::MethodId],
}

impl<'a> Resolver<'a> {
    fn string(&self, idx: u32) -> String {
        self.strings
            .get(idx as usize)
            .cloned()
            .unwrap_or_default()
    }

    fn type_name(&self, type_idx: u32) -> String {
        match self.type_ids.get(type_idx as usize) {
            Some(&s) => descriptor_to_java(&self.string(s)),
            None => String::new(),
        }
    }

    fn field_ref(&self, field_idx: u32) -> String {
        match self.field_ids.get(field_idx as usize) {
            Some(f) => {
                let class = self.type_name(f.class_idx as u32);
                let name = self.string(f.name_idx);
                if class.is_empty() {
                    name
                } else {
                    format!("{class}.{name}")
                }
            }
            None => format!("field@{field_idx}"),
        }
    }

    fn method_ref(&self, method_idx: u32) -> String {
        match self.method_ids.get(method_idx as usize) {
            Some(m) => {
                let class = self.type_name(m.class_idx as u32);
                let name = self.string(m.name_idx);
                if class.is_empty() {
                    name
                } else {
                    format!("{class}.{name}")
                }
            }
            None => format!("method@{method_idx}"),
        }
    }
}

/// Read a sized unsigned little-endian integer of `len` bytes (1..=8) into a
/// zero-extended u64 (used for char/float/double which are right-zero-padded).
fn read_sized_unsigned(r: &mut Reader, len: usize) -> Result<u64> {
    let mut value: u64 = 0;
    for i in 0..len {
        let b = r.u8()? as u64;
        value |= b << (8 * i);
    }
    Ok(value)
}

/// Read a sized signed little-endian integer of `len` bytes, sign-extended to
/// i64 from the high bit of the most-significant (last) byte.
fn read_sized_signed(r: &mut Reader, len: usize) -> Result<i64> {
    let mut value: u64 = 0;
    let mut last: u8 = 0;
    for i in 0..len {
        last = r.u8()?;
        value |= (last as u64) << (8 * i);
    }
    // Sign-extend from bit (len*8 - 1).
    if len < 8 && (last & 0x80) != 0 {
        let mask = !0u64 << (len * 8);
        value |= mask;
    }
    Ok(value as i64)
}

/// Decode one `encoded_value`.
pub fn read_encoded_value(r: &mut Reader, res: &Resolver) -> Result<EncodedValue> {
    let header = r.u8()?;
    let value_type = header & 0x1f;
    let value_arg = (header >> 5) & 0x07;
    let size = value_arg as usize + 1; // bytes for sized payloads

    let value = match value_type {
        VALUE_BYTE => EncodedValue::Byte(read_sized_signed(r, 1)? as i8),
        VALUE_SHORT => EncodedValue::Short(read_sized_signed(r, size)? as i16),
        VALUE_CHAR => EncodedValue::Char(read_sized_unsigned(r, size)? as u16),
        VALUE_INT => EncodedValue::Int(read_sized_signed(r, size)? as i32),
        VALUE_LONG => EncodedValue::Long(read_sized_signed(r, size)?),
        VALUE_FLOAT => {
            // Right-zero-padded to 4 bytes, low bytes are the high-order bits.
            let bits = (read_sized_unsigned(r, size)? << (8 * (4 - size))) as u32;
            EncodedValue::Float(f32::from_bits(bits))
        }
        VALUE_DOUBLE => {
            let bits = read_sized_unsigned(r, size)? << (8 * (8 - size));
            EncodedValue::Double(f64::from_bits(bits))
        }
        VALUE_METHOD_TYPE => EncodedValue::MethodType(read_sized_unsigned(r, size)? as u32),
        VALUE_METHOD_HANDLE => EncodedValue::MethodHandle(read_sized_unsigned(r, size)? as u32),
        VALUE_STRING => {
            let idx = read_sized_unsigned(r, size)? as u32;
            EncodedValue::String(res.string(idx))
        }
        VALUE_TYPE => {
            let idx = read_sized_unsigned(r, size)? as u32;
            EncodedValue::Type(res.type_name(idx))
        }
        VALUE_FIELD => {
            let idx = read_sized_unsigned(r, size)? as u32;
            EncodedValue::Field(res.field_ref(idx))
        }
        VALUE_METHOD => {
            let idx = read_sized_unsigned(r, size)? as u32;
            EncodedValue::Method(res.method_ref(idx))
        }
        VALUE_ENUM => {
            let idx = read_sized_unsigned(r, size)? as u32;
            EncodedValue::Enum(res.field_ref(idx))
        }
        VALUE_ARRAY => EncodedValue::Array(read_encoded_array(r, res)?),
        VALUE_ANNOTATION => EncodedValue::Annotation(read_encoded_annotation(r, res)?),
        VALUE_NULL => EncodedValue::Null,
        VALUE_BOOLEAN => EncodedValue::Boolean(value_arg != 0),
        _ => EncodedValue::Null,
    };
    Ok(value)
}

/// Decode an `encoded_array`: `size:uleb128` followed by `size` values.
pub fn read_encoded_array(r: &mut Reader, res: &Resolver) -> Result<Vec<EncodedValue>> {
    let size = r.uleb128()? as usize;
    let mut out = Vec::with_capacity(size);
    for _ in 0..size {
        out.push(read_encoded_value(r, res)?);
    }
    Ok(out)
}

/// Decode an `encoded_annotation`: `type_idx:uleb128`, `size:uleb128`, then
/// `size` `(name_idx:uleb128, value)` pairs.
pub fn read_encoded_annotation(r: &mut Reader, res: &Resolver) -> Result<Annotation> {
    let type_idx = r.uleb128()?;
    let size = r.uleb128()? as usize;
    let type_name = res.type_name(type_idx);
    let mut elements = Vec::with_capacity(size);
    for _ in 0..size {
        let name_idx = r.uleb128()?;
        let name = res.string(name_idx);
        let value = read_encoded_value(r, res)?;
        elements.push((name, value));
    }
    Ok(Annotation {
        type_name,
        elements,
    })
}

impl fmt::Display for EncodedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodedValue::Byte(v) => write!(f, "{v}"),
            EncodedValue::Short(v) => write!(f, "{v}"),
            EncodedValue::Char(v) => match char::from_u32(*v as u32) {
                Some(c) => write!(f, "'{}'", escape_char(c)),
                None => write!(f, "{v}"),
            },
            EncodedValue::Int(v) => write!(f, "{v}"),
            EncodedValue::Long(v) => write!(f, "{v}L"),
            EncodedValue::Float(v) => write!(f, "{v}f"),
            EncodedValue::Double(v) => write!(f, "{v}"),
            EncodedValue::MethodType(idx) => write!(f, "methodType@{idx}"),
            EncodedValue::MethodHandle(idx) => write!(f, "methodHandle@{idx}"),
            EncodedValue::String(s) => write!(f, "\"{}\"", escape_string(s)),
            // A `Type` value is a class literal in source.
            EncodedValue::Type(t) => write!(f, "{}.class", simple_type(t)),
            EncodedValue::Field(s) => write!(f, "{}", source_member(s)),
            EncodedValue::Method(s) => write!(f, "{}", source_member(s)),
            EncodedValue::Enum(s) => write!(f, "{}", source_member(s)),
            EncodedValue::Array(items) => {
                write!(f, "{{")?;
                for (i, it) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{it}")?;
                }
                write!(f, "}}")
            }
            EncodedValue::Annotation(a) => {
                write!(f, "@{}", simple_type(&a.type_name))?;
                if !a.elements.is_empty() {
                    write!(f, "(")?;
                    for (i, (name, val)) in a.elements.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(f, "{name} = {val}")?;
                    }
                    write!(f, ")")?;
                }
                Ok(())
            }
            EncodedValue::Null => write!(f, "null"),
            EncodedValue::Boolean(b) => write!(f, "{b}"),
        }
    }
}

/// Simple (unqualified) name of a Java-dotted type, keeping inner-class tails.
fn simple_type(java_name: &str) -> String {
    let base = java_name.strip_suffix("[]").unwrap_or(java_name);
    base.rsplit('.').next().unwrap_or(base).replace('$', ".")
}

/// Render a resolved member reference (`pkg.Class.MEMBER`) as `Class.MEMBER`.
fn source_member(member: &str) -> String {
    match member.rfind('.') {
        Some(idx) => {
            let (class, name) = (&member[..idx], &member[idx + 1..]);
            format!("{}.{}", simple_type(class), name)
        }
        None => member.to_string(),
    }
}

fn escape_char(c: char) -> String {
    match c {
        '\'' => "\\'".to_string(),
        '\\' => "\\\\".to_string(),
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
        c => c.to_string(),
    }
}

fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}
