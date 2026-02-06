//! Type descriptor (JVM/Dalvik) parsing and Java-source rendering.

/// Convert a single type descriptor (`Ljava/lang/String;`, `[I`, `V`) to a
/// Java source type (`java.lang.String`, `int[]`, `void`).
pub fn descriptor_to_java(d: &str) -> String {
    let bytes = d.as_bytes();
    let mut i = 0;
    let mut dims = 0;
    while i < bytes.len() && bytes[i] == b'[' {
        dims += 1;
        i += 1;
    }
    let base = if i >= bytes.len() {
        String::new()
    } else {
        match bytes[i] {
            b'V' => "void".to_string(),
            b'Z' => "boolean".to_string(),
            b'B' => "byte".to_string(),
            b'S' => "short".to_string(),
            b'C' => "char".to_string(),
            b'I' => "int".to_string(),
            b'J' => "long".to_string(),
            b'F' => "float".to_string(),
            b'D' => "double".to_string(),
            b'L' => {
                let rest = &d[i + 1..];
                let end = rest.find(';').unwrap_or(rest.len());
                rest[..end].replace('/', ".")
            }
            b'T' => {
                // Type variable from a generic signature.
                let rest = &d[i + 1..];
                let end = rest.find(';').unwrap_or(rest.len());
                rest[..end].to_string()
            }
            _ => d[i..].to_string(),
        }
    };
    let mut out = base;
    for _ in 0..dims {
        out.push_str("[]");
    }
    out
}

/// The simple (unqualified) name of a class descriptor or dotted name.
pub fn simple_name(java_name: &str) -> String {
    let last = java_name
        .rsplit(|c| c == '.' || c == '/')
        .next()
        .unwrap_or(java_name);
    // Inner classes use `$` — keep the trailing segment readable.
    last.rsplit('$').next().unwrap_or(last).to_string()
}

/// Package name (dotted) of a Java class name.
pub fn package_of(java_name: &str) -> String {
    match java_name.rfind('.') {
        Some(idx) => java_name[..idx].to_string(),
        None => String::new(),
    }
}

/// Render a method shorty character to a coarse Java type (for fallbacks).
pub fn shorty_to_java(c: char) -> &'static str {
    match c {
        'V' => "void",
        'Z' => "boolean",
        'B' => "byte",
        'S' => "short",
        'C' => "char",
        'I' => "int",
        'J' => "long",
        'F' => "float",
        'D' => "double",
        _ => "Object",
    }
}

/// True if the descriptor is a "wide" type (long/double) occupying a register pair.
pub fn is_wide(d: &str) -> bool {
    d == "J" || d == "D"
}
