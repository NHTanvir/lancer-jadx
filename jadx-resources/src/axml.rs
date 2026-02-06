//! Android binary XML (AXML) decoder → structured tree + pretty XML text.

use crate::error::{ResError, Result};
use crate::pool::{StringPool, RES_STRING_POOL_TYPE};
use crate::reader::{Buf, ChunkHeader};
use crate::value;

const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_NAMESPACE: u16 = 0x0100;
const RES_XML_END_NAMESPACE: u16 = 0x0101;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const RES_XML_END_ELEMENT: u16 = 0x0103;
const RES_XML_CDATA: u16 = 0x0104;
const RES_XML_RESOURCE_MAP: u16 = 0x0180;

pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

#[derive(Debug, Clone)]
pub struct XmlAttr {
    pub prefix: Option<String>,
    pub name: String,
    pub value: String,
}

impl XmlAttr {
    pub fn qualified(&self) -> String {
        match &self.prefix {
            Some(p) if !p.is_empty() => format!("{p}:{}", self.name),
            _ => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum XmlNode {
    Element(XmlElement),
    Text(String),
}

#[derive(Debug, Clone, Default)]
pub struct XmlElement {
    pub name: String,
    pub attrs: Vec<XmlAttr>,
    pub children: Vec<XmlNode>,
}

impl XmlElement {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|a| a.name == name).map(|a| a.value.as_str())
    }

    /// Recursively collect descendants (including self) with a given tag.
    pub fn find_all<'a>(&'a self, tag: &str, out: &mut Vec<&'a XmlElement>) {
        if self.name == tag {
            out.push(self);
        }
        for c in &self.children {
            if let XmlNode::Element(e) = c {
                e.find_all(tag, out);
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AxmlDocument {
    pub strings: StringPool,
    pub root: Option<XmlElement>,
    pub namespaces: Vec<(String, String)>,
    /// `RES_XML_RESOURCE_MAP` contents: one resource id per string-pool entry,
    /// indexed in parallel with `strings`. Used to recover an attribute name
    /// when its name string is empty but its index maps to a known framework
    /// `android:` attribute resource id.
    pub resource_map: Vec<u32>,
}

/// Map a framework `android:` attribute resource id to its attribute name, for
/// the small set of attributes that matter to manifest reconstruction. This is
/// best-effort: ids not listed fall back to the binary string-pool name.
pub fn android_attr_name(res_id: u32) -> Option<&'static str> {
    match res_id {
        0x0101_0000 => Some("theme"),
        0x0101_0001 => Some("label"),
        0x0101_0002 => Some("icon"),
        0x0101_0003 => Some("name"),
        0x0101_000e => Some("enabled"),
        0x0101_000f => Some("debuggable"),
        0x0101_0010 => Some("exported"),
        0x0101_0011 => Some("process"),
        0x0101_0018 => Some("authorities"),
        0x0101_001e => Some("permission"),
        0x0101_0020 => Some("minSdkVersion"),
        0x0101_021b => Some("versionCode"),
        0x0101_021c => Some("versionName"),
        0x0101_0270 => Some("targetActivity"),
        0x0101_0271 => Some("targetSdkVersion"),
        0x0101_0288 => Some("required"),
        0x0101_028a => Some("glEsVersion"),
        0x0101_0291 => Some("allowBackup"),
        0x0102_0094 => Some("networkSecurityConfig"),
        0x0102_004f => Some("usesCleartextTraffic"),
        _ => None,
    }
}

impl AxmlDocument {
    /// Decode a binary `AndroidManifest.xml` / layout / resource XML.
    pub fn decode(data: &[u8]) -> Result<AxmlDocument> {
        let mut b = Buf::new(data);
        let top = ChunkHeader::read(&mut b)?;
        if top.type_id != RES_XML_TYPE {
            return Err(ResError::BadChunk {
                expected: RES_XML_TYPE,
                found: top.type_id,
                offset: 0,
            });
        }

        let mut strings = StringPool::default();
        let mut doc_namespaces: Vec<(String, String)> = Vec::new();
        let mut ns_stack: Vec<(String, String)> = Vec::new();
        let mut elem_stack: Vec<XmlElement> = Vec::new();
        let mut root: Option<XmlElement> = None;
        let mut resource_map: Vec<u32> = Vec::new();

        let mut pos = top.start + top.header_size as usize;
        while pos + 8 <= data.len() {
            let mut cb = Buf::at(data, pos);
            let ch = ChunkHeader::read(&mut cb)?;
            if ch.chunk_size == 0 {
                break;
            }
            let body = ch.start + ch.header_size as usize;
            match ch.type_id {
                RES_STRING_POOL_TYPE => {
                    strings = StringPool::parse(data, ch.start)?;
                }
                RES_XML_RESOURCE_MAP => {
                    // Body is a flat array of u32 resource ids, one per string
                    // in the pool (parallel index). Length is derived from the
                    // chunk size after the header.
                    let map_bytes = (ch.chunk_size as usize).saturating_sub(ch.header_size as usize);
                    let count = map_bytes / 4;
                    let mut mb = Buf::at(data, body);
                    resource_map.clear();
                    resource_map.reserve(count);
                    for _ in 0..count {
                        match mb.u32() {
                            Ok(id) => resource_map.push(id),
                            Err(_) => break,
                        }
                    }
                }
                RES_XML_START_NAMESPACE => {
                    let mut nb = Buf::at(data, body);
                    let prefix = strings.get_or(nb.u32()?, "");
                    let uri = strings.get_or(nb.u32()?, "");
                    ns_stack.push((prefix.clone(), uri.clone()));
                    doc_namespaces.push((prefix, uri));
                }
                RES_XML_END_NAMESPACE => {
                    ns_stack.pop();
                }
                RES_XML_START_ELEMENT => {
                    let elem = parse_start_element(data, body, &strings, &ns_stack, &resource_map)?;
                    elem_stack.push(elem);
                }
                RES_XML_END_ELEMENT => {
                    if let Some(done) = elem_stack.pop() {
                        if let Some(parent) = elem_stack.last_mut() {
                            parent.children.push(XmlNode::Element(done));
                        } else {
                            root = Some(done);
                        }
                    }
                }
                RES_XML_CDATA => {
                    let mut tb = Buf::at(data, body);
                    let text = strings.get_or(tb.u32()?, "");
                    if let Some(parent) = elem_stack.last_mut() {
                        parent.children.push(XmlNode::Text(text));
                    }
                }
                _ => {}
            }
            pos = ch.end().max(pos + 8);
        }

        Ok(AxmlDocument {
            strings,
            root,
            namespaces: doc_namespaces,
            resource_map,
        })
    }

    /// Render the decoded document as pretty-printed XML text.
    pub fn to_xml_string(&self) -> String {
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        if let Some(root) = &self.root {
            write_element(&mut out, root, 0, &self.namespaces);
        }
        out
    }
}

fn parse_start_element(
    data: &[u8],
    body: usize,
    strings: &StringPool,
    ns_stack: &[(String, String)],
    resource_map: &[u32],
) -> Result<XmlElement> {
    let mut b = Buf::at(data, body);
    let _ns = b.u32()?;
    let name = strings.get_or(b.u32()?, "");
    let _attr_start = b.u16()?;
    let _attr_size = b.u16()?;
    let attr_count = b.u16()? as usize;
    let _id_index = b.u16()?;
    let _class_index = b.u16()?;
    let _style_index = b.u16()?;

    let mut attrs = Vec::with_capacity(attr_count);
    for _ in 0..attr_count {
        let ns_uri = strings.get(b.u32()?).map(|s| s.to_string());
        let name_idx = b.u32()?;
        let aname = attr_name(name_idx, strings, resource_map);
        let raw_value = b.u32()?;
        let _size = b.u16()?;
        let _res0 = b.u8()?;
        let data_type = b.u8()?;
        let adata = b.u32()?;
        let value = if raw_value != 0xffff_ffff {
            strings.get_or(raw_value, "")
        } else {
            value::format(data_type, adata, strings)
        };
        let prefix = ns_uri.as_deref().map(|uri| prefix_for(uri, ns_stack));
        attrs.push(XmlAttr {
            prefix,
            name: aname,
            value,
        });
    }

    Ok(XmlElement {
        name,
        attrs,
        children: Vec::new(),
    })
}

/// Resolve an attribute name from its string-pool index, falling back to the
/// resource map when the pooled name is empty. Many obfuscated/optimized APKs
/// leave attribute name strings blank and rely solely on the parallel
/// `RES_XML_RESOURCE_MAP` entry to identify the `android:` attribute.
fn attr_name(name_idx: u32, strings: &StringPool, resource_map: &[u32]) -> String {
    let pooled = strings.get_or(name_idx, "");
    if !pooled.is_empty() {
        return pooled;
    }
    if name_idx != 0xffff_ffff {
        if let Some(&res_id) = resource_map.get(name_idx as usize) {
            if let Some(known) = android_attr_name(res_id) {
                return known.to_string();
            }
        }
    }
    pooled
}

fn prefix_for(uri: &str, ns_stack: &[(String, String)]) -> String {
    for (p, u) in ns_stack.iter().rev() {
        if u == uri {
            return p.clone();
        }
    }
    if uri == ANDROID_NS {
        "android".to_string()
    } else {
        String::new()
    }
}

fn write_element(out: &mut String, e: &XmlElement, depth: usize, namespaces: &[(String, String)]) {
    let indent = "    ".repeat(depth);
    out.push_str(&indent);
    out.push('<');
    out.push_str(&e.name);

    if depth == 0 {
        for (prefix, uri) in namespaces {
            if prefix.is_empty() {
                out.push_str(&format!(" xmlns=\"{}\"", escape(uri)));
            } else {
                out.push_str(&format!(" xmlns:{}=\"{}\"", prefix, escape(uri)));
            }
        }
    }
    for a in &e.attrs {
        out.push_str(&format!(" {}=\"{}\"", a.qualified(), escape(&a.value)));
    }

    let element_children: Vec<&XmlNode> = e.children.iter().collect();
    if element_children.is_empty() {
        out.push_str("/>\n");
        return;
    }
    out.push_str(">\n");
    for c in &e.children {
        match c {
            XmlNode::Element(child) => write_element(out, child, depth + 1, namespaces),
            XmlNode::Text(t) => {
                let t = t.trim();
                if !t.is_empty() {
                    out.push_str(&"    ".repeat(depth + 1));
                    out.push_str(&escape(t));
                    out.push('\n');
                }
            }
        }
    }
    out.push_str(&indent);
    out.push_str(&format!("</{}>\n", e.name));
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
