//! Kotlin source emitter.
//!
//! Per the plan, idiomatic Kotlin restoration (coroutines, data classes,
//! smart-casts) is an explicit Lancer-divergence area. This implementation
//! renders the Java AST and applies pattern rewrites (getter/setter → property
//! hints, `new X()` → `X()`, type mapping, lambda-friendly syntax) to produce
//! recognisable Kotlin — a strong baseline the AI pass can refine.

use crate::args::JadxArgs;
use jadx_dex::{DexClass, DexFile};
use regex::Regex;
use std::sync::OnceLock;

/// Render a Kotlin compilation unit for one DEX class.
pub fn render_class(dex: &DexFile, class: &DexClass, args: &JadxArgs) -> String {
    let java = super::java::render_class(dex, class, args);
    kotlinize(&java)
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
    let p = patterns();
    let mut out = String::new();
    for raw in java.lines() {
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
    out = out.replace("new ", "");
    out = out.replace(" instanceof ", " is ");
    out = out.replace(".class", "::class.java");
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
    match java {
        "int" => "Int",
        "long" => "Long",
        "boolean" => "Boolean",
        "byte" => "Byte",
        "short" => "Short",
        "char" => "Char",
        "float" => "Float",
        "double" => "Double",
        "void" => "Unit",
        "Object" | "java.lang.Object" => "Any",
        "String" | "java.lang.String" => "String",
        other => other,
    }
    .to_string()
}
