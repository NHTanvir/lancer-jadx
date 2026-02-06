//! AndroidManifest.xml structured extraction (components, permissions, flags).

use crate::axml::{AxmlDocument, XmlElement, XmlNode};

#[derive(Debug, Clone, Default)]
pub struct DataSpec {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    pub path: Option<String>,
    pub path_prefix: Option<String>,
    pub path_pattern: Option<String>,
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data: Vec<DataSpec>,
}

impl IntentFilter {
    pub fn is_launcher(&self) -> bool {
        self.actions.iter().any(|a| a.ends_with("action.MAIN"))
            && self.categories.iter().any(|c| c.ends_with("category.LAUNCHER"))
    }
    /// Deep-link schemes declared by this filter.
    pub fn schemes(&self) -> Vec<String> {
        self.data.iter().filter_map(|d| d.scheme.clone()).collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Component {
    /// `activity` / `service` / `receiver` / `provider`.
    pub kind: String,
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
}

impl Component {
    /// Effective exported state (explicit, or implied by an intent-filter).
    pub fn is_exported(&self) -> bool {
        match self.exported {
            Some(v) => v,
            None => !self.intent_filters.is_empty(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManifestInfo {
    pub package: String,
    pub version_name: Option<String>,
    pub version_code: Option<String>,
    pub min_sdk: Option<String>,
    pub target_sdk: Option<String>,
    pub uses_permissions: Vec<String>,
    pub permissions_defined: Vec<String>,
    pub components: Vec<Component>,
    pub debuggable: Option<bool>,
    pub allow_backup: Option<bool>,
    pub uses_cleartext_traffic: Option<bool>,
    pub network_security_config: Option<String>,
}

impl ManifestInfo {
    pub fn from_document(doc: &AxmlDocument) -> ManifestInfo {
        let mut info = ManifestInfo::default();
        let root = match &doc.root {
            Some(r) => r,
            None => return info,
        };
        info.package = root.attr("package").unwrap_or("").to_string();
        info.version_name = root.attr("versionName").map(str::to_string);
        info.version_code = root.attr("versionCode").map(str::to_string);

        // uses-sdk
        let mut sdks = Vec::new();
        root.find_all("uses-sdk", &mut sdks);
        if let Some(sdk) = sdks.first() {
            info.min_sdk = sdk.attr("minSdkVersion").map(str::to_string);
            info.target_sdk = sdk.attr("targetSdkVersion").map(str::to_string);
        }

        // uses-permission
        let mut perms = Vec::new();
        root.find_all("uses-permission", &mut perms);
        for p in perms {
            if let Some(n) = p.attr("name") {
                info.uses_permissions.push(n.to_string());
            }
        }
        let mut defined = Vec::new();
        root.find_all("permission", &mut defined);
        for p in defined {
            if let Some(n) = p.attr("name") {
                info.permissions_defined.push(n.to_string());
            }
        }

        // application flags
        let mut apps = Vec::new();
        root.find_all("application", &mut apps);
        if let Some(app) = apps.first() {
            info.debuggable = app.attr("debuggable").map(parse_bool);
            info.allow_backup = app.attr("allowBackup").map(parse_bool);
            info.uses_cleartext_traffic = app.attr("usesCleartextTraffic").map(parse_bool);
            info.network_security_config = app.attr("networkSecurityConfig").map(str::to_string);
        }

        for kind in ["activity", "activity-alias", "service", "receiver", "provider"] {
            let mut comps = Vec::new();
            root.find_all(kind, &mut comps);
            for c in comps {
                info.components.push(parse_component(kind, c));
            }
        }

        info
    }

    pub fn exported_components(&self) -> impl Iterator<Item = &Component> {
        self.components.iter().filter(|c| c.is_exported())
    }
}

fn parse_component(kind: &str, e: &XmlElement) -> Component {
    let mut comp = Component {
        kind: kind.to_string(),
        name: e.attr("name").unwrap_or("").to_string(),
        exported: e.attr("exported").map(parse_bool),
        permission: e.attr("permission").map(str::to_string),
        intent_filters: Vec::new(),
    };
    for child in &e.children {
        if let XmlNode::Element(f) = child {
            if f.name == "intent-filter" {
                comp.intent_filters.push(parse_intent_filter(f));
            }
        }
    }
    comp
}

fn parse_intent_filter(e: &XmlElement) -> IntentFilter {
    let mut f = IntentFilter::default();
    for child in &e.children {
        if let XmlNode::Element(c) = child {
            match c.name.as_str() {
                "action" => {
                    if let Some(n) = c.attr("name") {
                        f.actions.push(n.to_string());
                    }
                }
                "category" => {
                    if let Some(n) = c.attr("name") {
                        f.categories.push(n.to_string());
                    }
                }
                "data" => {
                    f.data.push(DataSpec {
                        scheme: c.attr("scheme").map(str::to_string),
                        host: c.attr("host").map(str::to_string),
                        port: c.attr("port").map(str::to_string),
                        path: c.attr("path").map(str::to_string),
                        path_prefix: c.attr("pathPrefix").map(str::to_string),
                        path_pattern: c.attr("pathPattern").map(str::to_string),
                        mime_type: c.attr("mimeType").map(str::to_string),
                    });
                }
                _ => {}
            }
        }
    }
    f
}

fn parse_bool(s: &str) -> bool {
    s.eq_ignore_ascii_case("true") || s == "1"
}
