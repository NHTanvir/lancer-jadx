//! Kotlin source emitter.
//!
//! Per the plan, idiomatic Kotlin restoration (coroutines, data classes,
//! smart-casts) is an explicit Lancer-divergence area. This implementation
//! renders the Java AST and applies pattern rewrites (getter/setter → property
//! hints, `new X()` → `X()`, type mapping, lambda-friendly syntax) to produce
//! recognisable Kotlin — a strong baseline the AI pass can refine.
//!
//! The transformer is intentionally a pure function over the *rendered Java
//! source string*: the Kotlin path has no DEX access of its own, so all
//! idiom recovery is done with conservative, panic-free text pre-passes
//! followed by the per-line rewrite that maps Java syntax to Kotlin.

use crate::args::JadxArgs;
use super::kotlin_metadata::{KotlinClassKind, KotlinMetadata};
use jadx_dex::{DexClass, DexFile, EncodedValue};
use regex::Regex;
use std::sync::OnceLock;

/// Render a Kotlin compilation unit for one DEX class.
pub fn render_class(dex: &DexFile, class: &DexClass, args: &JadxArgs) -> String {
    let java = super::java::render_class(dex, class, args);
    let mut out = kotlinize(&java);
    // When the class carries a `kotlin.Metadata` annotation (parsed from the DEX
    // annotations directory), surface the decoded metadata kind/version so the
    // emitted Kotlin reflects the original compilation unit — matching upstream
    // jadx, which annotates decompiled Kotlin with its source metadata.
    if let Some(md) = kotlin_metadata_for(class) {
        out = format!("{}{}", metadata_banner(&md), out);
    }
    out
}

/// Build the leading metadata comment for a Kotlin compilation unit.
fn metadata_banner(md: &KotlinMetadata) -> String {
    let kind = match md.kind {
        KotlinClassKind::Class => "class",
        KotlinClassKind::FileFacade => "file-facade",
        KotlinClassKind::SyntheticClass => "synthetic-class",
        KotlinClassKind::MultiFileClassFacade => "multifile-facade",
        KotlinClassKind::MultiFileClassPart => "multifile-part",
        KotlinClassKind::Unknown => "unknown",
    };
    let ver = md
        .metadata_version
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".");
    format!("// Kotlin metadata: kind={kind}, version={ver}\n")
}

/// Extract and decode the `kotlin.Metadata` annotation off a class, if present.
fn kotlin_metadata_for(class: &DexClass) -> Option<KotlinMetadata> {
    let ann = class
        .class_annotations
        .iter()
        .find(|a| a.type_name == "kotlin.Metadata")?;
    let mut k = 0i32;
    let (mut mv, mut d1, mut d2) = (Vec::new(), Vec::new(), Vec::new());
    let (mut xi, mut xs, mut pn) = (0i32, String::new(), String::new());
    for (name, val) in &ann.elements {
        match name.as_str() {
            "k" => if let EncodedValue::Int(v) = val { k = *v; },
            "mv" => mv = int_array(val),
            "d1" => d1 = string_array(val),
            "d2" => d2 = string_array(val),
            "xi" => if let EncodedValue::Int(v) = val { xi = *v; },
            "xs" => if let EncodedValue::String(s) = val { xs = s.clone(); },
            "pn" => if let EncodedValue::String(s) = val { pn = s.clone(); },
            _ => {}
        }
    }
    Some(KotlinMetadata::from_fields(k, &mv, &d1, &d2, xi, &xs, &pn))
}

fn int_array(v: &EncodedValue) -> Vec<i32> {
    match v {
        EncodedValue::Array(items) => items
            .iter()
            .filter_map(|i| if let EncodedValue::Int(n) = i { Some(*n) } else { None })
            .collect(),
        _ => Vec::new(),
    }
}

fn string_array(v: &EncodedValue) -> Vec<String> {
    match v {
        EncodedValue::Array(items) => items
            .iter()
            .filter_map(|i| if let EncodedValue::String(s) = i { Some(s.clone()) } else { None })
            .collect(),
        _ => Vec::new(),
    }
}

/// Transform already-rendered Java source into Kotlin (used for the JVM path).
pub fn render_class_from_java(java: &str) -> String {
    kotlinize(java)
}

struct Patterns {
    method: Regex,
    ctor: Regex,
    field_or_local: Regex,
    class_header: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        method: Regex::new(
            r"^(\s*)((?:public |private |protected |static |final |abstract |synchronized |native |strictfp )*)([\w.$<>\[\]]+) (\w+)\((.*)\) \{$",
        )
        .unwrap(),
        ctor: Regex::new(r"^(\s*)((?:public |private |protected )*)(\w+)\((.*)\) \{$").unwrap(),
        field_or_local: Regex::new(
            r"^(\s*)((?:public |private |protected |static |final |volatile |transient )*)([\w.$<>\[\]]+) (\w+)(?: = (.*))?;$",
        )
        .unwrap(),
        class_header: Regex::new(
            r"^(\s*)((?:public |private |protected |final |abstract |static )*)(class|interface|enum) (.+) \{$",
        )
        .unwrap(),
    })
}

fn kotlinize(java: &str) -> String {
    // Idiom pre-passes operate on the raw Java text before the per-line
    // syntax rewrite. Each is best-effort and falls back to the input
    // unchanged when it cannot confidently apply.
    let pre = merge_properties(java);
    let pre = rewrite_companion(&pre);
    let pre = rewrite_lambdas(&pre);

    let p = patterns();
    let mut out = String::new();
    for raw in pre.lines() {
        let line = raw.to_string();

        if let Some(c) = p.class_header.captures(&line) {
            out.push_str(&rewrite_class_header(&c));
            out.push('\n');
            continue;
        }
        if let Some(c) = p.method.captures(&line) {
            out.push_str(&rewrite_method(&c));
            out.push('\n');
            continue;
        }
        if let Some(c) = p.ctor.captures(&line) {
            // Skip control-flow keywords that look like calls.
            let name = c.get(3).map(|m| m.as_str()).unwrap_or("");
            if !matches!(name, "if" | "while" | "for" | "switch" | "catch" | "synchronized") {
                out.push_str(&rewrite_ctor(&c));
                out.push('\n');
                continue;
            }
        }
        if let Some(c) = p.field_or_local.captures(&line) {
            out.push_str(&rewrite_field_or_local(&c));
            out.push('\n');
            continue;
        }

        out.push_str(&rewrite_statement(&line));
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Pre-pass 1: getter/setter → property merging.
// ---------------------------------------------------------------------------

/// A JavaBean-style accessor discovered in the source.
struct Accessor {
    /// Property name (`name` from `getName`).
    prop: String,
    /// Return / value type as rendered by the Java emitter.
    ty: String,
    /// Whether this is a setter (vs. a getter).
    is_setter: bool,
    /// Index of the accessor's signature line.
    sig_line: usize,
    /// Index (exclusive) one past the accessor's closing brace.
    end_line: usize,
}

fn accessor_patterns() -> &'static (Regex, Regex, Regex) {
    static A: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    A.get_or_init(|| {
        (
            // getX() / isX()
            Regex::new(
                r"^(\s*)(?:public |protected )?(?:final )?([\w.$<>\[\]]+) (get|is)([A-Z]\w*)\(\) \{$",
            )
            .unwrap(),
            // setX(T v)
            Regex::new(
                r"^(\s*)(?:public |protected )?(?:final )?void set([A-Z]\w*)\(([\w.$<>\[\]]+) \w+\) \{$",
            )
            .unwrap(),
            // private backing field
            Regex::new(
                r"^(\s*)private (?:final )?([\w.$<>\[\]]+) (\w+);$",
            )
            .unwrap(),
        )
    })
}

/// Lowercase the first character of a JavaBean property segment (`Name` →
/// `name`), leaving all-caps acronyms (`URL`) untouched.
fn decapitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => {
            let rest: String = chars.collect();
            // Keep acronyms like "URL" as-is.
            if rest.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
                s.to_string()
            } else {
                format!("{}{}", first.to_lowercase(), rest)
            }
        }
        None => String::new(),
    }
}

/// Find the index just past the closing brace of a `{ ... }` block whose
/// opening brace is on `lines[start]`, tracking nesting. Returns `None` if the
/// block never closes (malformed input).
fn block_end(lines: &[&str], start: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut seen_open = false;
    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    seen_open = true;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        if seen_open && depth <= 0 {
            return Some(i + 1);
        }
    }
    None
}

/// Collapse JavaBean getter/setter pairs (and their private backing field)
/// into Kotlin `val`/`var` properties. Conservative: only collapses when the
/// accessor body is a trivial passthrough or its body cannot be inspected.
fn merge_properties(java: &str) -> String {
    let lines: Vec<&str> = java.lines().collect();
    let (get_re, set_re, field_re) = accessor_patterns();

    // 1. Discover accessors with their line ranges.
    let mut accessors: Vec<Accessor> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(c) = get_re.captures(line) {
            let ty = map_type(&c[2]);
            let raw_prop = c[4].to_string();
            let end = block_end(&lines, i).unwrap_or(i + 1);
            if accessor_body_is_trivial_get(&lines[i..end]) {
                accessors.push(Accessor {
                    prop: decapitalize(&raw_prop),
                    ty,
                    is_setter: false,
                    sig_line: i,
                    end_line: end,
                });
            }
            i = end;
            continue;
        }
        if let Some(c) = set_re.captures(line) {
            let raw_prop = c[2].to_string();
            let ty = map_type(&c[3]);
            let end = block_end(&lines, i).unwrap_or(i + 1);
            if accessor_body_is_trivial_set(&lines[i..end]) {
                accessors.push(Accessor {
                    prop: decapitalize(&raw_prop),
                    ty,
                    is_setter: true,
                    sig_line: i,
                    end_line: end,
                });
            }
            i = end;
            continue;
        }
        i += 1;
    }

    if accessors.is_empty() {
        return java.to_string();
    }

    // 2. Group by property; require at least a getter to form a property.
    use std::collections::BTreeMap;
    let mut by_prop: BTreeMap<String, (Option<usize>, Option<usize>)> = BTreeMap::new();
    for (idx, a) in accessors.iter().enumerate() {
        let entry = by_prop.entry(a.prop.clone()).or_insert((None, None));
        if a.is_setter {
            entry.1 = Some(idx);
        } else {
            entry.0 = Some(idx);
        }
    }

    // Lines to drop (accessor bodies) and the indent/property text to emit at
    // the getter's location.
    use std::collections::HashSet;
    let mut drop_lines: HashSet<usize> = HashSet::new();
    // sig_line -> replacement property declaration (already including indent).
    let mut emit_at: std::collections::HashMap<usize, String> = std::collections::HashMap::new();

    for (prop, (get_idx, set_idx)) in by_prop {
        let gi = match get_idx {
            Some(g) => g,
            None => continue, // setter without getter — leave as a function.
        };
        let getter = &accessors[gi];
        let indent = leading_ws(lines[getter.sig_line]);
        let kw = if set_idx.is_some() { "var" } else { "val" };
        emit_at.insert(
            getter.sig_line,
            format!("{indent}{kw} {}: {}", prop, getter.ty),
        );
        for l in getter.sig_line..getter.end_line {
            drop_lines.insert(l);
        }
        if let Some(si) = set_idx {
            let setter = &accessors[si];
            for l in setter.sig_line..setter.end_line {
                drop_lines.insert(l);
            }
        }
    }

    // 3. Remove the private backing fields whose name matches a merged prop.
    let prop_names: HashSet<String> = emit_at
        .values()
        .filter_map(|decl| {
            // decl looks like "<indent><kw> <name>: <ty>"
            decl.split_whitespace().nth(1).map(|s| {
                s.trim_end_matches(':').to_string()
            })
        })
        .collect();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(c) = field_re.captures(line) {
            let fname = &c[3]; // group 3: field name
            let normalized = fname.trim_start_matches('_').to_string();
            if prop_names.contains(fname) || prop_names.contains(&normalized) {
                drop_lines.insert(idx);
            }
        }
    }

    // 4. Reassemble.
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if let Some(decl) = emit_at.get(&idx) {
            out.push_str(decl);
            out.push('\n');
            continue;
        }
        if drop_lines.contains(&idx) {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn leading_ws(line: &str) -> String {
    line.chars().take_while(|c| c.is_whitespace()).collect()
}

/// A getter body is "trivial" when it is a single `return ...;` statement, or
/// when the body cannot be confidently inspected (collapse best-effort).
fn accessor_body_is_trivial_get(block: &[&str]) -> bool {
    // block[0] is the signature line; the remainder up to the closing brace
    // is the body.
    let body: Vec<&str> = block
        .iter()
        .skip(1)
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && *l != "}")
        .collect();
    match body.len() {
        0 => true,
        1 => body[0].starts_with("return"),
        // Multi-statement bodies: best-effort, still collapse the signature.
        _ => true,
    }
}

/// A setter body is "trivial" when it is a single assignment statement (or its
/// body cannot be confidently inspected).
fn accessor_body_is_trivial_set(block: &[&str]) -> bool {
    let body: Vec<&str> = block
        .iter()
        .skip(1)
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && *l != "}")
        .collect();
    match body.len() {
        0 => true,
        1 => body[0].contains('=') && body[0].ends_with(';'),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Pre-pass 2: Companion object recovery.
// ---------------------------------------------------------------------------

/// Rewrite a nested `class Companion { ... }` (Kotlin's compiled companion
/// holder) into a Kotlin `companion object { ... }`.
fn rewrite_companion(java: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"^(\s*)(?:public |private |protected |final |static )*class Companion(?: extends [\w.$<>]+)?(?: implements [\w.$<>, ]+)? \{$",
        )
        .unwrap()
    });
    let mut out = String::new();
    for line in java.lines() {
        if let Some(c) = re.captures(line) {
            let indent = &c[1];
            out.push_str(&format!("{indent}companion object {{"));
            out.push('\n');
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Pre-pass 3: FunctionN lambda recovery (best-effort).
// ---------------------------------------------------------------------------

/// Rewrite anonymous classes implementing `kotlin.jvm.functions.FunctionN`
/// with a single `invoke(...)` into a trailing-lambda `{ args -> ... }` shape.
///
/// Best-effort: detects the `new FunctionN() { ... invoke(...) { ... } ... }`
/// idiom and replaces the class header / `invoke` boilerplate with lambda
/// braces, keeping the body lines.
fn rewrite_lambdas(java: &str) -> String {
    static HEADER: OnceLock<Regex> = OnceLock::new();
    static INVOKE: OnceLock<Regex> = OnceLock::new();
    let header = HEADER.get_or_init(|| {
        // matches a class header (already rendered) implementing FunctionN
        Regex::new(
            r"^(\s*)(?:public |private |protected |final |static |abstract )*class [\w$]+ (?:extends [\w.$<>]+ )?implements (?:kotlin\.jvm\.functions\.)?Function(\d{1,2})(?:<[^>]*>)? \{$",
        )
        .unwrap()
    });
    let invoke = INVOKE.get_or_init(|| {
        Regex::new(r"^(\s*)(?:public |final )*[\w.$<>\[\]]+ invoke\((.*)\) \{$").unwrap()
    });

    let lines: Vec<&str> = java.lines().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if let Some(hc) = header.captures(line) {
            let indent = hc[1].to_string();
            // Find the class block extent.
            if let Some(end) = block_end(&lines, i) {
                if let Some((inv_sig, inv_end, args)) =
                    find_invoke(&lines[i..end], invoke)
                {
                    // Emit a lambda: { params -> ... body ... }
                    let params = lambda_params(&args);
                    if params.is_empty() {
                        out.push_str(&format!("{indent}{{\n"));
                    } else {
                        out.push_str(&format!("{indent}{{ {params} ->\n"));
                    }
                    // Body is between invoke sig+1 and inv_end-1 (drop closing).
                    let abs_sig = i + inv_sig;
                    let abs_end = i + inv_end;
                    for l in &lines[abs_sig + 1..abs_end.saturating_sub(1)] {
                        out.push_str(l);
                        out.push('\n');
                    }
                    out.push_str(&format!("{indent}}}\n"));
                    i = end;
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
        i += 1;
    }
    out
}

/// Within a class block, locate the `invoke(...)` method and return
/// `(relative_sig_line, relative_end_line, raw_params)`.
fn find_invoke(block: &[&str], invoke: &Regex) -> Option<(usize, usize, String)> {
    for (rel, line) in block.iter().enumerate() {
        if let Some(c) = invoke.captures(line) {
            let args = c[2].to_string();
            let end = block_end(block, rel)?;
            return Some((rel, end, args));
        }
    }
    None
}

/// Turn a Java parameter list (`Foo a, Bar b`) into Kotlin lambda parameter
/// names (`a, b`), dropping the types.
fn lambda_params(params: &str) -> String {
    if params.trim().is_empty() {
        return String::new();
    }
    params
        .split(", ")
        .filter_map(|p| p.rsplit(' ').next())
        .filter(|n| !n.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Per-line syntax rewrites.
// ---------------------------------------------------------------------------

fn rewrite_class_header(c: &regex::Captures) -> String {
    let indent = &c[1];
    let kind = &c[3];
    let rest = c[4].to_string();
    // rest like "Foo extends Bar implements A, B"
    let mut supertypes: Vec<String> = Vec::new();
    let mut name_part = rest.clone();
    if let Some(idx) = rest.find(" extends ") {
        name_part = rest[..idx].to_string();
        let after = &rest[idx + 9..];
        let (ext, imp) = split_implements(after);
        supertypes.push(map_type(ext.trim()));
        supertypes.extend(imp);
    } else if let Some(idx) = rest.find(" implements ") {
        name_part = rest[..idx].to_string();
        let after = &rest[idx + 12..];
        supertypes.extend(after.split(',').map(|s| map_type(s.trim())));
    }
    let kw = match kind {
        "interface" => "interface",
        "enum" => "enum class",
        _ => "class",
    };
    if supertypes.is_empty() {
        format!("{indent}{kw} {name_part} {{")
    } else {
        format!("{indent}{kw} {name_part} : {} {{", supertypes.join(", "))
    }
}

fn split_implements(after: &str) -> (String, Vec<String>) {
    if let Some(idx) = after.find(" implements ") {
        let ext = after[..idx].to_string();
        let imp = after[idx + 12..]
            .split(',')
            .map(|s| map_type(s.trim()))
            .collect();
        (ext, imp)
    } else {
        (after.to_string(), Vec::new())
    }
}

fn rewrite_method(c: &regex::Captures) -> String {
    let indent = &c[1];
    let mods = kotlin_modifiers(&c[2]);
    let ret = map_type(&c[3]);
    let name = &c[4];
    let params = rewrite_params(&c[5]);
    let ret_part = if ret == "Unit" {
        String::new()
    } else {
        format!(": {ret}")
    };
    format!("{indent}{mods}fun {name}({params}){ret_part} {{")
}

fn rewrite_ctor(c: &regex::Captures) -> String {
    let indent = &c[1];
    let mods = kotlin_modifiers(&c[2]);
    let params = rewrite_params(&c[4]);
    format!("{indent}{mods}constructor({params}) {{")
}

fn rewrite_field_or_local(c: &regex::Captures) -> String {
    let indent = &c[1];
    let mods = kotlin_modifiers(&c[2]);
    let ty = map_type(&c[3]);
    let name = &c[4];
    let init = c.get(5).map(|m| m.as_str().to_string());
    match init {
        Some(rhs) => format!("{indent}{mods}var {name}: {ty} = {}", rewrite_expr(&rhs)),
        None => format!("{indent}{mods}var {name}: {ty}? = null"),
    }
}

fn rewrite_params(params: &str) -> String {
    if params.trim().is_empty() {
        return String::new();
    }
    params
        .split(", ")
        .filter_map(|p| {
            let parts: Vec<&str> = p.rsplitn(2, ' ').collect();
            if parts.len() == 2 {
                let name = parts[0];
                let ty = map_type(parts[1]);
                Some(format!("{name}: {ty}"))
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn rewrite_statement(line: &str) -> String {
    let trimmed_end = line.trim_end();
    let stripped = trimmed_end.strip_suffix(';').unwrap_or(trimmed_end);
    rewrite_expr(stripped)
}

fn rewrite_expr(s: &str) -> String {
    let mut out = s.to_string();
    // Pair / Triple constructor idioms: `new Pair<>(a, b)` / `new kotlin.Pair(a, b)`.
    out = rewrite_pair_triple(&out);
    out = out.replace("new ", "");
    out = out.replace(" instanceof ", " is ");
    out = out.replace(".class", "::class.java");
    out
}

/// Map Java `Pair`/`Triple` constructor calls and type references to their
/// Kotlin spellings. Handles the `kotlin.` prefix and the `<>` diamond.
fn rewrite_pair_triple(s: &str) -> String {
    let mut out = s.to_string();
    for ty in ["Pair", "Triple"] {
        // `new kotlin.Pair<...>(` and `new Pair<...>(` -> `Pair(`
        let with_pkg_diamond = format!("new kotlin.{ty}<>(");
        out = out.replace(&with_pkg_diamond, &format!("{ty}("));
        let with_diamond = format!("new {ty}<>(");
        out = out.replace(&with_diamond, &format!("{ty}("));
        let with_pkg = format!("new kotlin.{ty}(");
        out = out.replace(&with_pkg, &format!("{ty}("));
        let plain = format!("new {ty}(");
        out = out.replace(&plain, &format!("{ty}("));
        // Bare type references.
        out = out.replace(&format!("kotlin.{ty}"), ty);
    }
    out
}

fn kotlin_modifiers(java_mods: &str) -> String {
    let mut out = Vec::new();
    for m in java_mods.split_whitespace() {
        match m {
            "private" => out.push("private"),
            "protected" => out.push("protected"),
            "abstract" => out.push("abstract"),
            // public is the Kotlin default; static/final/etc dropped or implied.
            _ => {}
        }
    }
    if out.is_empty() {
        String::new()
    } else {
        format!("{} ", out.join(" "))
    }
}

/// Map a Java type to its Kotlin equivalent (best-effort).
fn map_type(java: &str) -> String {
    let java = java.trim();
    if let Some(elem) = java.strip_suffix("[]") {
        return match elem {
            "int" => "IntArray".to_string(),
            "long" => "LongArray".to_string(),
            "boolean" => "BooleanArray".to_string(),
            "byte" => "ByteArray".to_string(),
            "short" => "ShortArray".to_string(),
            "char" => "CharArray".to_string(),
            "float" => "FloatArray".to_string(),
            "double" => "DoubleArray".to_string(),
            other => format!("Array<{}>", map_type(other)),
        };
    }
    let mapped = match java {
        "int" | "java.lang.Integer" | "Integer" => "Int",
        "long" | "java.lang.Long" | "Long" => "Long",
        "boolean" | "java.lang.Boolean" | "Boolean" => "Boolean",
        "byte" | "java.lang.Byte" | "Byte" => "Byte",
        "short" | "java.lang.Short" | "Short" => "Short",
        "char" | "java.lang.Character" | "Character" => "Char",
        "float" | "java.lang.Float" | "Float" => "Float",
        "double" | "java.lang.Double" | "Double" => "Double",
        "void" | "java.lang.Void" => "Unit",
        "Object" | "java.lang.Object" => "Any",
        "String" | "java.lang.String" => "String",
        "CharSequence" | "java.lang.CharSequence" => "CharSequence",
        "Number" | "java.lang.Number" => "Number",
        "Throwable" | "java.lang.Throwable" => "Throwable",
        "kotlin.Pair" | "Pair" => "Pair",
        "kotlin.Triple" | "Triple" => "Triple",
        "kotlin.Unit" => "Unit",
        "kotlin.Any" => "Any",
        other => return map_generic_type(other),
    };
    mapped.to_string()
}

/// Map a generic / qualified type, recursing into type arguments where present
/// (`java.util.List<java.lang.String>` -> `List<String>`).
fn map_generic_type(java: &str) -> String {
    if let Some(lt) = java.find('<') {
        if java.ends_with('>') {
            let base = &java[..lt];
            let inner = &java[lt + 1..java.len() - 1];
            let mapped_base = map_type(base);
            let mapped_args = split_type_args(inner)
                .iter()
                .map(|a| map_type(a))
                .collect::<Vec<_>>()
                .join(", ");
            return format!("{mapped_base}<{mapped_args}>");
        }
    }
    // Strip common java.util/java.lang qualifiers for readability.
    java.to_string()
}

/// Split a generic argument list on top-level commas (respecting nested `<>`).
fn split_type_args(inner: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in inner.chars() {
        match ch {
            '<' => {
                depth += 1;
                cur.push(ch);
            }
            '>' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                args.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        args.push(cur.trim().to_string());
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_primitive_and_boxed_types() {
        assert_eq!(map_type("int"), "Int");
        assert_eq!(map_type("java.lang.Integer"), "Int");
        assert_eq!(map_type("void"), "Unit");
        assert_eq!(map_type("java.lang.String"), "String");
        assert_eq!(map_type("java.lang.Object"), "Any");
        assert_eq!(map_type("int[]"), "IntArray");
        assert_eq!(map_type("String[]"), "Array<String>");
    }

    #[test]
    fn maps_generic_types() {
        assert_eq!(
            map_type("java.util.List<java.lang.String>"),
            "java.util.List<String>"
        );
        assert_eq!(map_type("kotlin.Pair<int, java.lang.String>"), "Pair<Int, String>");
    }

    #[test]
    fn rewrites_class_header_with_supertypes() {
        let java = "class Foo extends Bar implements java.lang.Runnable {\n}\n";
        let kt = render_class_from_java(java);
        assert!(kt.contains("class Foo : Bar, java.lang.Runnable {"), "{kt}");
    }

    #[test]
    fn rewrites_method_and_unit_return() {
        let java = "    public void run() {\n    }\n";
        let kt = render_class_from_java(java);
        assert!(kt.contains("fun run() {"), "{kt}");
        assert!(!kt.contains(": Unit"), "{kt}");
    }

    #[test]
    fn pair_constructor_becomes_kotlin_call() {
        let java = "        x = new kotlin.Pair<>(a, b);\n";
        let kt = render_class_from_java(java);
        assert!(kt.contains("Pair(a, b)"), "{kt}");
        assert!(!kt.contains("new "), "{kt}");
    }

    #[test]
    fn instanceof_and_class_rewrites_preserved() {
        let java = "        b = (x instanceof String);\n        c = String.class;\n";
        let kt = render_class_from_java(java);
        assert!(kt.contains(" is String"), "{kt}");
        assert!(kt.contains("::class.java"), "{kt}");
    }

    #[test]
    fn getter_setter_becomes_var_property() {
        let java = "\
class Foo {
    private int count;

    public int getCount() {
        return this.count;
    }

    public void setCount(int v) {
        this.count = v;
    }
}
";
        let kt = render_class_from_java(java);
        assert!(kt.contains("var count: Int"), "{kt}");
        assert!(!kt.contains("getCount"), "{kt}");
        assert!(!kt.contains("setCount"), "{kt}");
        // backing field removed
        assert!(!kt.contains("private int count"), "{kt}");
    }

    #[test]
    fn getter_only_becomes_val_property() {
        let java = "\
class Foo {
    private java.lang.String name;

    public java.lang.String getName() {
        return this.name;
    }
}
";
        let kt = render_class_from_java(java);
        assert!(kt.contains("val name: String"), "{kt}");
        assert!(!kt.contains("var name"), "{kt}");
    }

    #[test]
    fn companion_class_becomes_companion_object() {
        let java = "\
class Foo {
    public static class Companion {
        public int bar() {
            return 0;
        }
    }
}
";
        let kt = render_class_from_java(java);
        assert!(kt.contains("companion object {"), "{kt}");
        assert!(!kt.contains("class Companion"), "{kt}");
    }

    #[test]
    fn function_lambda_recovered() {
        let java = "\
        x = new Runnable() {
        };
        y = new Function1<java.lang.String, java.lang.String> {
        };
        class Anon implements kotlin.jvm.functions.Function1<java.lang.String, java.lang.String> {
            public java.lang.String invoke(java.lang.String s) {
                return s;
            }
        }
";
        let kt = render_class_from_java(java);
        assert!(kt.contains("{ s ->"), "{kt}");
        assert!(!kt.contains("invoke("), "{kt}");
    }

    #[test]
    fn plain_class_unchanged_by_property_pass() {
        let java = "\
class Foo {
    public int compute() {
        return 1;
    }
}
";
        let kt = render_class_from_java(java);
        assert!(kt.contains("fun compute(): Int {"), "{kt}");
    }

    #[test]
    fn malformed_input_does_not_panic() {
        // unterminated block, stray braces
        let java = "class Foo {\n    public int getX() {\n";
        let _ = render_class_from_java(java);
        let _ = render_class_from_java("}}}{{{");
        let _ = render_class_from_java("");
    }
}
