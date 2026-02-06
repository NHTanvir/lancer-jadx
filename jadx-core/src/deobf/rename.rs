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
    /// Honour `--deobf-use-sourcename`: prefer DEX `source_file` basenames.
    use_sourcename: bool,
}

impl Renamer {
    pub fn new(args: &JadxArgs) -> Self {
        Renamer {
            classes: HashMap::new(),
            members: HashMap::new(),
            min: args.deobf_min as usize,
            max: args.deobf_max as usize,
            enabled: args.deobf && args.rename_flags != RenameFlags::None,
            use_sourcename: args.deobf_use_sourcename,
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
        // Track new class names already in use so source-name-derived names stay unique.
        let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
        for dex in dex_files {
            for class in &dex.classes {
                let cname = jadx_dex::descriptor::simple_name(&dex.class_name(class));
                if self.is_candidate(&cname) && !self.classes.contains_key(&cname) {
                    let new_name = self
                        .use_sourcename
                        .then(|| source_name_for(dex.source_file(class), &cname))
                        .flatten()
                        .map(|base| unique_name(&base, &used))
                        .unwrap_or_else(|| format!("C{cls_n:04}Cls"));
                    cls_n += 1;
                    used.insert(new_name.clone());
                    self.classes.insert(cname, new_name);
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

/// Derive a usable simple class name from a DEX `source_file` value.
///
/// Returns `None` when the source name is absent, generic (`SourceFile`), or
/// just echoes the obfuscated short name — in those cases the caller falls back
/// to the synthetic `Cls` heuristic.
fn source_name_for(source_file: Option<&str>, obf_name: &str) -> Option<String> {
    let raw = source_file?.trim();
    if raw.is_empty() {
        return None;
    }
    // Strip directory components and the file extension (e.g. ".java"/".kt").
    let basename = raw.rsplit(|c| c == '/' || c == '\\').next().unwrap_or(raw);
    let stem = match basename.rfind('.') {
        Some(idx) => &basename[..idx],
        None => basename,
    };
    if stem.is_empty() || stem.eq_ignore_ascii_case("SourceFile") || stem == obf_name {
        return None;
    }
    let ident = sanitize_identifier(stem);
    // Reject names that sanitized down to nothing useful or back to the obf name.
    if ident.is_empty() || ident == obf_name {
        None
    } else {
        Some(ident)
    }
}

/// Sanitize an arbitrary string into a valid Java identifier.
fn sanitize_identifier(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    // Java identifiers cannot start with a digit.
    if out.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        out.insert(0, '_');
    }
    out
}

/// Ensure `base` is unique within `used` by appending a numeric suffix.
fn unique_name(base: &str, used: &std::collections::HashSet<String>) -> String {
    if !used.contains(base) {
        return base.to_string();
    }
    let mut n = 1usize;
    loop {
        let candidate = format!("{base}{n}");
        if !used.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
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
