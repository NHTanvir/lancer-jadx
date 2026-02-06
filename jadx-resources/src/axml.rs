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
                RES_XML_RESOURCE_MAP => { /* attribute resource ids — not needed */ }
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
                    let elem = parse_start_element(data, body, &strings, &ns_stack)?;
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
        let aname = strings.get_or(b.u32()?, "");
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
