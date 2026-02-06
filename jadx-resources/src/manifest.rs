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
pub struct UsesFeature {
    /// `android:name` of the feature, when named (hardware/software features).
    pub name: Option<String>,
    /// `android:glEsVersion`, when this is an OpenGL ES version requirement.
    pub gl_es_version: Option<String>,
    /// `android:required` — defaults to `true` per the platform when absent.
    pub required: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Component {
    /// `activity` / `activity-alias` / `service` / `receiver` / `provider`.
    pub kind: String,
    pub name: String,
    pub exported: Option<bool>,
    pub permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
    /// `android:targetActivity` for an `activity-alias`; `None` otherwise.
    pub target_activity: Option<String>,
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
    /// `<uses-feature>` declarations (hardware/software/GL ES requirements).
    pub uses_features: Vec<UsesFeature>,
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

        // uses-feature (hardware/software/GL ES requirements)
        let mut features = Vec::new();
        root.find_all("uses-feature", &mut features);
        for f in features {
            info.uses_features.push(UsesFeature {
                name: f.attr("name").map(str::to_string),
                gl_es_version: f.attr("glEsVersion").map(str::to_string),
                // Per the platform default, a feature is required unless
                // android:required="false" is set explicitly.
                required: f.attr("required").map(parse_bool).unwrap_or(true),
            });
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

    /// Required `<uses-feature>` declarations (android:required defaulting true).
    pub fn required_features(&self) -> impl Iterator<Item = &UsesFeature> {
        self.uses_features.iter().filter(|f| f.required)
    }

    /// `activity-alias` components, paired with the activity they target.
    pub fn activity_aliases(&self) -> impl Iterator<Item = (&Component, &str)> {
        self.components.iter().filter_map(|c| {
            if c.kind == "activity-alias" {
                Some((c, c.target_activity.as_deref().unwrap_or("")))
            } else {
                None
            }
        })
    }
}

impl UsesFeature {
    /// Best-effort display label: the feature name, else `glEsVersion`.
    pub fn label(&self) -> String {
        match (&self.name, &self.gl_es_version) {
            (Some(n), _) if !n.is_empty() => n.clone(),
            (_, Some(v)) => format!("glEsVersion={v}"),
            _ => String::new(),
        }
    }
}

fn parse_component(kind: &str, e: &XmlElement) -> Component {
    let mut comp = Component {
        kind: kind.to_string(),
        name: e.attr("name").unwrap_or("").to_string(),
        exported: e.attr("exported").map(parse_bool),
        permission: e.attr("permission").map(str::to_string),
        intent_filters: Vec::new(),
        target_activity: e.attr("targetActivity").map(str::to_string),
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
