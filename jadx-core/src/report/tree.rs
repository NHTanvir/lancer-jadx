//! JSON package tree of the decompiled project (for GUI / `--json-tree`).

use jadx_dex::access::{self, AccessKind};
use jadx_dex::DexFile;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct FieldNode {
    pub name: String,
    pub r#type: String,
    pub modifiers: String,
}

#[derive(Debug, Serialize)]
pub struct MethodNode {
    pub name: String,
    pub return_type: String,
    pub params: Vec<String>,
    pub modifiers: String,
}

#[derive(Debug, Serialize)]
pub struct ClassNode {
    pub name: String,
    pub package: String,
    pub simple_name: String,
    pub super_class: Option<String>,
    pub interfaces: Vec<String>,
    pub kind: String,
    pub fields: Vec<FieldNode>,
    pub methods: Vec<MethodNode>,
}

#[derive(Debug, Serialize)]
pub struct PackageNode {
    pub name: String,
    pub classes: Vec<ClassNode>,
}

#[derive(Debug, Serialize, Default)]
pub struct ProjectTree {
    pub packages: Vec<PackageNode>,
    pub class_count: usize,
}

/// Build a `ProjectTree` from all loaded DEX files.
pub fn build_tree(dex_files: &[DexFile]) -> ProjectTree {
    use std::collections::BTreeMap;
    let mut by_pkg: BTreeMap<String, Vec<ClassNode>> = BTreeMap::new();
    let mut count = 0usize;

    for dex in dex_files {
        for class in &dex.classes {
            let full = dex.class_name(class);
            let package = jadx_dex::descriptor::package_of(&full);
            let node = ClassNode {
                simple_name: jadx_dex::descriptor::simple_name(&full),
                package: package.clone(),
                super_class: dex.superclass_name(class),
                interfaces: dex.interface_names(class),
                kind: access::class_keyword(class.access_flags).to_string(),
                fields: class
                    .static_fields
                    .iter()
                    .chain(class.instance_fields.iter())
                    .map(|f| {
                        let fr = dex.field_entry_ref(f);
                        FieldNode {
                            name: fr.name,
                            r#type: fr.field_type,
                            modifiers: access::modifiers(f.access_flags, AccessKind::Field),
                        }
                    })
                    .collect(),
                methods: class
                    .direct_methods
                    .iter()
                    .chain(class.virtual_methods.iter())
                    .map(|m| {
                        let mr = dex.method_entry_ref(m);
                        MethodNode {
                            name: mr.name,
                            return_type: mr.return_type,
                            params: mr.params,
                            modifiers: access::modifiers(m.access_flags, AccessKind::Method),
                        }
                    })
                    .collect(),
                name: full,
            };
            by_pkg.entry(package).or_default().push(node);
            count += 1;
        }
    }

    ProjectTree {
        packages: by_pkg
            .into_iter()
            .map(|(name, classes)| PackageNode { name, classes })
            .collect(),
        class_count: count,
    }
}

/// Serialize the tree to pretty JSON.
pub fn to_json(tree: &ProjectTree) -> String {
    serde_json::to_string_pretty(tree).unwrap_or_else(|_| "{}".to_string())
}
