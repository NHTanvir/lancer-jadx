//! End-to-end decompile orchestration: load → decompile (parallel) → render →
//! deobfuscate → report → write outputs.

use crate::args::{JadxArgs, OutputFormat};
use crate::codegen;
use crate::deobf::{AiRenamer, Renamer};
use crate::input::{self, LoadedProject};
use crate::report::{self, Finding};
use crate::xref::XrefIndex;
use anyhow::{Context, Result};
use jadx_dex::{DexClass, DexFile};
use rayon::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

/// One decompiled class ready to write or display.
#[derive(Debug, Clone)]
pub struct DecompiledClass {
    pub full_name: String,
    pub package: String,
    pub simple_name: String,
    pub relative_path: String,
    pub source: String,
}

/// The loaded project + decompiler services.
pub struct Jadx {
    pub args: JadxArgs,
    pub project: LoadedProject,
    pub renamer: Renamer,
    pub ai: AiRenamer,
    /// Resource-id → `R.type.name` map for constant replacement (`--no-replace-consts`
    /// disables it). Built once at load from the decoded `resources.arsc`.
    pub res_consts: HashMap<i64, String>,
}

impl Jadx {
    /// Load all inputs declared in `args`.
    pub fn load(args: JadxArgs) -> Result<Jadx> {
        let mut project = LoadedProject::default();
        for path in &args.inputs {
            let loaded = input::load(path, &args)
                .with_context(|| format!("loading {}", path.display()))?;
            merge_project(&mut project, loaded);
        }
        let mut renamer = Renamer::new(&args);
        renamer.build(&project.dex_files);
        let ai = AiRenamer::new(args.ai_rename);
        let res_consts = build_res_consts(&project, &args);
        Ok(Jadx {
            args,
            project,
            renamer,
            ai,
            res_consts,
        })
    }

    pub fn class_count(&self) -> usize {
        self.project.class_count()
    }

    /// Build the cross-reference index.
    pub fn xref(&self) -> XrefIndex {
        XrefIndex::build(&self.project.dex_files)
    }

    fn ext(&self) -> &'static str {
        if self.args.kotlin {
            "kt"
        } else {
            "java"
        }
    }

    fn render_dex_class(&self, dex: &DexFile, class: &DexClass) -> DecompiledClass {
        let full = dex.class_name(class);
        let package = jadx_dex::descriptor::package_of(&full);
        let simple = jadx_dex::descriptor::simple_name(&full);
        let mut source = if self.args.kotlin {
            codegen::render_kotlin_class(dex, class, &self.args)
        } else {
            codegen::render_java_class(dex, class, &self.args)
        };
        if self.renamer.is_enabled() {
            source = self.renamer.apply_to_source(&source);
        }
        if !self.res_consts.is_empty() {
            source = self.apply_resource_consts(&source);
        }
        let path = format!(
            "{}/{}.{}",
            package.replace('.', "/"),
            simple,
            self.ext()
        );
        DecompiledClass {
            full_name: full,
            package,
            simple_name: simple,
            relative_path: path.trim_start_matches('/').to_string(),
            source,
        }
    }

    /// Replace bare resource-id integer literals (`2131230721`, `0x7f080001`)
    /// with their `R.type.name` form, resolved against the decoded ARSC table.
    /// Only large literals matching a known resource id are rewritten, so
    /// ordinary numeric constants are left untouched.
    fn apply_resource_consts(&self, src: &str) -> String {
        static RE: OnceLock<Regex> = OnceLock::new();
        let re = RE.get_or_init(|| {
            Regex::new(r"\b(0[xX][0-9a-fA-F]{7,8}|[0-9]{9,10})\b")
                .expect("static resource-id regex is valid")
        });
        re.replace_all(src, |caps: &regex::Captures| {
            let tok = &caps[1];
            let id = match tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
                Some(hex) => i64::from_str_radix(hex, 16).ok(),
                None => tok.parse::<i64>().ok(),
            };
            match id.and_then(|v| self.res_consts.get(&v)) {
                Some(name) => name.clone(),
                None => tok.to_string(),
            }
        })
        .into_owned()
    }

    /// Decompile every class (DEX + JVM), in parallel.
    pub fn decompile_all(&self) -> Vec<DecompiledClass> {
        let mut tasks: Vec<(&DexFile, &DexClass)> = Vec::new();
        for dex in &self.project.dex_files {
            for class in &dex.classes {
                if let Some(filter) = &self.args.single_class {
                    if !dex.class_name(class).contains(filter.as_str()) {
                        continue;
                    }
                }
                tasks.push((dex, class));
            }
        }

        let render = |(dex, class): &(&DexFile, &DexClass)| self.render_dex_class(dex, class);
        let mut out: Vec<DecompiledClass> = if self.args.threads_count > 1 {
            match rayon::ThreadPoolBuilder::new()
                .num_threads(self.args.threads_count)
                .build()
            {
                Ok(pool) => pool.install(|| tasks.par_iter().map(render).collect()),
                Err(_) => tasks.par_iter().map(render).collect(),
            }
        } else if self.args.threads_count == 1 {
            tasks.iter().map(render).collect()
        } else {
            tasks.par_iter().map(render).collect()
        };

        // JVM classes (structural).
        for jc in &self.project.jvm_classes {
            let pkg = jc.package();
            let simple = jc.simple_name();
            let mut source = jc.to_java(&self.args);
            if self.args.kotlin {
                source = codegen::kotlin::render_class_from_java(&source);
            }
            out.push(DecompiledClass {
                full_name: jc.name.clone(),
                package: pkg.clone(),
                simple_name: simple.clone(),
                relative_path: format!("{}/{}.{}", pkg.replace('.', "/"), simple, self.ext())
                    .trim_start_matches('/')
                    .to_string(),
                source,
            });
        }
        out
    }

    /// The decoded `AndroidManifest.xml` text, if present.
    pub fn manifest_xml(&self) -> Option<String> {
        self.project.manifest.as_ref().map(|m| m.to_xml_string())
    }

    /// Extract all string resources + a capped sample of DEX strings as JSON.
    pub fn extract_strings_json(&self) -> String {
        #[derive(serde::Serialize)]
        struct StringRes {
            name: String,
            value: String,
        }
        #[derive(serde::Serialize)]
        struct Out {
            resources: Vec<StringRes>,
            dex_strings: Vec<String>,
        }
        let mut resources = Vec::new();
        if let Some(arsc) = &self.project.resources {
            for e in arsc.of_type("string") {
                resources.push(StringRes {
                    name: e.name.clone(),
                    value: e.value.clone(),
                });
            }
        }
        let mut dex_strings = Vec::new();
        for dex in &self.project.dex_files {
            for s in &dex.strings {
                if s.len() >= 4 && !s.starts_with('L') {
                    dex_strings.push(s.clone());
                }
            }
        }
        dex_strings.sort();
        dex_strings.dedup();
        dex_strings.truncate(50_000);
        let out = Out {
            resources,
            dex_strings,
        };
        serde_json::to_string_pretty(&out).unwrap_or_else(|_| "{}".to_string())
    }

    /// JSON package tree.
    pub fn tree_json(&self) -> String {
        let tree = report::build_tree(&self.project.dex_files);
        report::tree_to_json(&tree)
    }

    /// Run the full findings scan (decompiled sources + manifest).
    pub fn run_findings(&self) -> Vec<Finding> {
        let classes = self.decompile_all();
        let pairs: Vec<(String, String)> = classes
            .iter()
            .map(|c| (c.relative_path.clone(), c.source.clone()))
            .collect();
        let mut findings = report::scan_sources(&pairs);
        if let Some(info) = &self.project.manifest_info {
            findings.extend(report::scan_manifest(info));
        }
        findings
    }

    /// Search decompiled source bodies for a regex pattern.
    pub fn find_pattern(&self, pattern: &str) -> Result<Vec<(String, usize, String)>> {
        let re = regex::Regex::new(pattern).context("invalid search pattern")?;
        let classes = self.decompile_all();
        let mut hits = Vec::new();
        for c in &classes {
            for (i, line) in c.source.lines().enumerate() {
                if re.is_match(line) {
                    hits.push((c.relative_path.clone(), i + 1, line.trim().to_string()));
                }
            }
        }
        Ok(hits)
    }

    /// Write the full decompile (sources + resources + manifest) to `output_dir`.
    ///
    /// With `--export-gradle` the output is laid out as a buildable Gradle
    /// project (`settings.gradle`, `build.gradle`, `app/src/main/...`); otherwise
    /// the classic `sources/` + `resources/` split is used. `--cfg` / `--raw-cfg`
    /// additionally emit per-method Graphviz `.dot` graphs under `cfg/`.
    pub fn write_output(&self) -> Result<()> {
        let out = &self.args.output_dir;
        fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;

        let gradle = self.args.export_gradle;
        if gradle {
            self.write_gradle_scaffold(out)?;
        }
        // Source / resource roots depend on the output layout.
        let src_root = if gradle {
            out.join("app/src/main/java")
        } else {
            out.join("sources")
        };
        let res_main = if gradle {
            out.join("app/src/main")
        } else {
            out.join("resources")
        };

        if !self.args.no_src {
            let classes = self.decompile_all();
            for c in &classes {
                match self.args.output_format {
                    OutputFormat::Json => {
                        let path = src_root.join(format!(
                            "{}.json",
                            c.relative_path.trim_end_matches(&format!(".{}", self.ext()))
                        ));
                        write_file(&path, &serde_json::to_string_pretty(&serde_json::json!({
                            "name": c.full_name,
                            "source": c.source,
                        })).unwrap_or_default())?;
                    }
                    OutputFormat::Java => {
                        write_file(&src_root.join(&c.relative_path), &c.source)?;
                    }
                }
            }
            if self.renamer.is_enabled() && self.args.deobf_rewrite_cfg {
                write_file(&out.join("deobf-map.txt"), &self.renamer.to_mapping_text())?;
            }
            // Persist the cross-reference index for incremental re-runs / GUI.
            let _ = self.xref().save(&out.join("xref.json"));
        }

        // Per-method control-flow graphs (Graphviz DOT).
        if self.args.cfg || self.args.raw_cfg {
            self.write_cfgs(&out.join("cfg"))?;
        }

        if !self.args.no_res && self.args.decode_resources {
            if let Some(xml) = self.manifest_xml() {
                write_file(&res_main.join("AndroidManifest.xml"), &xml)?;
            }
            if let Some(arsc) = &self.project.resources {
                let strings_xml = render_strings_xml(arsc);
                write_file(&res_main.join("res/values/strings.xml"), &strings_xml)?;
            }
        }
        Ok(())
    }

    /// Emit a Graphviz `.dot` control-flow graph per method under `cfg_root`.
    fn write_cfgs(&self, cfg_root: &Path) -> Result<()> {
        let raw = self.args.raw_cfg;
        for dex in &self.project.dex_files {
            for class in &dex.classes {
                let full = dex.class_name(class);
                if let Some(filter) = &self.args.single_class {
                    if !full.contains(filter.as_str()) {
                        continue;
                    }
                }
                let pkg_dir = jadx_dex::descriptor::package_of(&full).replace('.', "/");
                for g in crate::codegen::cfg::class_cfgs_dot(dex, class, raw) {
                    let path = cfg_root.join(&pkg_dir).join(format!("{}.dot", g.label));
                    write_file(&path, &g.dot)?;
                }
            }
        }
        Ok(())
    }

    /// Write a minimal buildable Gradle project skeleton (`--export-gradle`).
    fn write_gradle_scaffold(&self, out: &Path) -> Result<()> {
        let info = self.project.manifest_info.as_ref();
        let pkg = info
            .map(|i| i.package.clone())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "recovered.app".to_string());
        let name = pkg.rsplit('.').next().unwrap_or("app").to_string();
        let version_code = info
            .and_then(|i| i.version_code.clone())
            .unwrap_or_else(|| "1".to_string());
        let version_name = info
            .and_then(|i| i.version_name.clone())
            .unwrap_or_else(|| "1.0".to_string());

        write_file(
            &out.join("settings.gradle"),
            &format!("rootProject.name = '{name}'\ninclude ':app'\n"),
        )?;
        write_file(
            &out.join("build.gradle"),
            "// Generated by lancer-jadx --export-gradle\n\
             buildscript {\n    repositories { google(); mavenCentral() }\n\
             \x20   dependencies { classpath 'com.android.tools.build:gradle:8.1.0' }\n}\n\n\
             allprojects {\n    repositories { google(); mavenCentral() }\n}\n",
        )?;
        let app = format!(
            "// Generated by lancer-jadx --export-gradle\n\
             plugins {{\n    id 'com.android.application'\n}}\n\n\
             android {{\n    namespace '{pkg}'\n    compileSdk 34\n\n\
             \x20   defaultConfig {{\n        applicationId '{pkg}'\n        minSdk 21\n\
             \x20       targetSdk 34\n        versionCode {version_code}\n\
             \x20       versionName '{version_name}'\n    }}\n}}\n"
        );
        write_file(&out.join("app/build.gradle"), &app)?;
        Ok(())
    }
}

/// Build the resource-id → `R.type.name` map used for constant replacement.
/// Empty when `--no-replace-consts` is set, resources are skipped, or no ARSC
/// table was decoded.
fn build_res_consts(project: &LoadedProject, args: &JadxArgs) -> HashMap<i64, String> {
    let mut map = HashMap::new();
    if args.no_replace_consts || !args.decode_resources {
        return map;
    }
    if let Some(arsc) = &project.resources {
        for e in arsc.entries.values() {
            map.insert(e.id as i64, e.r_name());
        }
    }
    map
}

fn merge_project(into: &mut LoadedProject, from: LoadedProject) {
    if into.source_path.as_os_str().is_empty() {
        into.source_path = from.source_path;
    }
    into.dex_files.extend(from.dex_files);
    into.jvm_classes.extend(from.jvm_classes);
    if into.manifest.is_none() {
        into.manifest = from.manifest;
        into.manifest_info = from.manifest_info;
    }
    if into.resources.is_none() {
        into.resources = from.resources;
    }
    into.raw_files.extend(from.raw_files);
}

fn write_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn render_strings_xml(arsc: &jadx_resources::Arsc) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<resources>\n");
    for e in arsc.of_type("string") {
        out.push_str(&format!(
            "    <string name=\"{}\">{}</string>\n",
            e.name,
            xml_escape(&e.value)
        ));
    }
    out.push_str("</resources>\n");
    out
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
