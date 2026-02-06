//! Heuristic deobfuscation: rename short / synthetic identifiers to readable,
//! deterministic names (`a` → `C0000Cls`, etc.), persistable for re-runs.

use crate::args::{JadxArgs, RenameFlags};
use jadx_dex::DexFile;
use std::collections::HashMap;

#[derive(Debug, Default, Clone)]
pub struct Renamer {
    /// original simple class name → new name.
    pub classes: HashMap<String, String>,
    /// original member (field/method) name → new name.
    pub members: HashMap<String, String>,
    min: usize,
    max: usize,
    enabled: bool,
}

impl Renamer {
    pub fn new(args: &JadxArgs) -> Self {
        Renamer {
            classes: HashMap::new(),
            members: HashMap::new(),
            min: args.deobf_min as usize,
            max: args.deobf_max as usize,
            enabled: args.deobf && args.rename_flags != RenameFlags::None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether a name is a deobfuscation candidate (too short/long or synthetic).
    pub fn is_candidate(&self, name: &str) -> bool {
        if name.starts_with('<') {
            return false; // <init>/<clinit>
        }
        let len = name.chars().count();
        len < self.min || len > self.max || looks_synthetic(name)
    }

    /// Build rename maps across all loaded DEX files.
    pub fn build(&mut self, dex_files: &[DexFile]) {
        if !self.enabled {
            return;
        }
        let mut cls_n = 0usize;
        let mut mem_n = 0usize;
        for dex in dex_files {
            for class in &dex.classes {
                let cname = jadx_dex::descriptor::simple_name(&dex.class_name(class));
                if self.is_candidate(&cname) && !self.classes.contains_key(&cname) {
                    self.classes.insert(cname, format!("C{cls_n:04}Cls"));
                    cls_n += 1;
                }
                for f in class.static_fields.iter().chain(class.instance_fields.iter()) {
                    let n = dex.field_entry_ref(f).name;
                    if self.is_candidate(&n) && !self.members.contains_key(&n) {
                        self.members.insert(n, format!("field{mem_n}"));
                        mem_n += 1;
                    }
                }
                for m in class.direct_methods.iter().chain(class.virtual_methods.iter()) {
                    let n = dex.method_entry_ref(m).name;
                    if self.is_candidate(&n) && !self.members.contains_key(&n) {
                        self.members.insert(n, format!("method{mem_n}"));
                        mem_n += 1;
                    }
                }
            }
        }
    }

    /// Apply the rename map textually to generated source (whole-word matches).
    pub fn apply_to_source(&self, src: &str) -> String {
        if !self.enabled || (self.classes.is_empty() && self.members.is_empty()) {
            return src.to_string();
        }
        let mut out = String::with_capacity(src.len());
        for token in tokenize(src) {
            match token {
                Token::Ident(id) => {
                    if let Some(new) = self.classes.get(id).or_else(|| self.members.get(id)) {
                        out.push_str(new);
                    } else {
                        out.push_str(id);
                    }
                }
                Token::Other(s) => out.push_str(s),
            }
        }
        out
    }

    /// Serialize the mapping (for `--deobf-rewrite-cfg`).
    pub fn to_mapping_text(&self) -> String {
        let mut lines = Vec::new();
        let mut classes: Vec<_> = self.classes.iter().collect();
        classes.sort();
        for (k, v) in classes {
            lines.push(format!("c {k} = {v}"));
        }
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort();
        for (k, v) in members {
            lines.push(format!("m {k} = {v}"));
        }
        lines.join("\n")
    }
}

fn looks_synthetic(name: &str) -> bool {
    name.contains("$$")
        || (name.len() <= 2 && name.chars().all(|c| c.is_ascii_alphabetic()))
}

enum Token<'a> {
    Ident(&'a str),
    Other(&'a str),
}

fn tokenize(src: &str) -> Vec<Token<'_>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            out.push(Token::Ident(&src[start..i]));
        } else {
            let start = i;
            while i < bytes.len()
                && !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'$')
            {
                i += 1;
            }
            out.push(Token::Other(&src[start..i]));
        }
    }
    out
}
