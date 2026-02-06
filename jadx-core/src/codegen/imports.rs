//! Import collection + simple-name resolution for the Java emitter.

use std::collections::BTreeMap;

#[derive(Default)]
pub struct Imports {
    /// simple name → fully-qualified name (first one wins; collisions stay FQN).
    map: BTreeMap<String, String>,
    no_imports: bool,
    self_package: String,
}

impl Imports {
    pub fn new(no_imports: bool, self_package: &str) -> Self {
        Imports {
            map: BTreeMap::new(),
            no_imports,
            self_package: self_package.to_string(),
        }
    }

    /// Register a Java type and return the name to use in source.
    pub fn use_type(&mut self, java_type: &str) -> String {
        // Peel array dimensions.
        let mut base = java_type;
        let mut dims = 0;
        while let Some(stripped) = base.strip_suffix("[]") {
            base = stripped;
            dims += 1;
        }
        let suffix = "[]".repeat(dims);

        if base.is_empty() || is_primitive(base) || !base.contains('.') {
            return format!("{base}{suffix}");
        }
        if self.no_imports {
            return format!("{base}{suffix}");
        }

        let simple = base.rsplit('.').next().unwrap_or(base).to_string();
        match self.map.get(&simple) {
            Some(existing) if existing == base => format!("{simple}{suffix}"),
            Some(_) => format!("{base}{suffix}"), // collision: keep fully qualified
            None => {
                self.map.insert(simple.clone(), base.to_string());
                format!("{simple}{suffix}")
            }
        }
    }

    /// Render the `import ...;` block (java.lang and same-package are skipped).
    pub fn render(&self) -> String {
        if self.no_imports {
            return String::new();
        }
        let mut lines: Vec<String> = Vec::new();
        for fqn in self.map.values() {
            let pkg = jadx_dex::descriptor::package_of(fqn);
            if pkg == "java.lang" || pkg.is_empty() || pkg == self.self_package {
                continue;
            }
            lines.push(format!("import {fqn};"));
        }
        lines.sort();
        lines.dedup();
        if lines.is_empty() {
            String::new()
        } else {
            format!("{}\n\n", lines.join("\n"))
        }
    }
}

pub fn is_primitive(s: &str) -> bool {
    matches!(
        s,
        "void" | "boolean" | "byte" | "short" | "char" | "int" | "long" | "float" | "double"
    )
}
