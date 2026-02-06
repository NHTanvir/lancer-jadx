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
use std::fs;
use std::path::Path;

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
        Ok(Jadx {
            args,
            project,
            renamer,
            ai,
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
    pub fn write_output(&self) -> Result<()> {
        let out = &self.args.output_dir;
        fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;

        if !self.args.no_src {
            let classes = self.decompile_all();
            let src_root = out.join("sources");
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
        }

        if !self.args.no_res && self.args.decode_resources {
            let res_root = out.join("resources");
            if let Some(xml) = self.manifest_xml() {
                write_file(&res_root.join("AndroidManifest.xml"), &xml)?;
            }
            if let Some(arsc) = &self.project.resources {
                let strings_xml = render_strings_xml(arsc);
                write_file(&res_root.join("res/values/strings.xml"), &strings_xml)?;
            }
        }
        Ok(())
    }
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
