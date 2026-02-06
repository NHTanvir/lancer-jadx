//! Input dispatch: open `.apk/.aab/.xapk/.dex/.odex/.aar/.jar/.class/.zip` and
//! materialise a [`LoadedProject`] (DEX images, JVM classes, manifest, resources,
//! raw files).

pub mod aar;
pub mod apk;
pub mod class;
pub mod dex;
pub mod jar;

use crate::args::JadxArgs;
use anyhow::Context;
use jadx_dex::DexFile;
use jadx_resources::{Arsc, AxmlDocument, ManifestInfo};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

pub use class::JvmClass;

/// A raw, non-decompiled file pulled from the input container.
#[derive(Debug, Clone)]
pub struct RawFile {
    pub name: String,
    pub data: Vec<u8>,
}

/// Everything we managed to load from an input path.
#[derive(Default)]
pub struct LoadedProject {
    pub source_path: PathBuf,
    pub dex_files: Vec<DexFile>,
    pub jvm_classes: Vec<JvmClass>,
    pub manifest: Option<AxmlDocument>,
    pub manifest_info: Option<ManifestInfo>,
    pub resources: Option<Arsc>,
    pub raw_files: Vec<RawFile>,
}

impl LoadedProject {
    pub fn class_count(&self) -> usize {
        self.dex_files.iter().map(|d| d.classes.len()).sum::<usize>() + self.jvm_classes.len()
    }
}

/// Load one input path, dispatching on its extension and contents.
pub fn load(path: &Path, args: &JadxArgs) -> anyhow::Result<LoadedProject> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading input file {}", path.display()))?;
    let mut project = LoadedProject {
        source_path: path.to_path_buf(),
        ..Default::default()
    };

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match ext.as_str() {
        "dex" | "odex" => dex::load_dex(&bytes, &mut project)?,
        "class" => {
            if let Ok(jc) = JvmClass::parse(&bytes) {
                project.jvm_classes.push(jc);
            }
        }
        "jar" => jar::load_jar(&bytes, &mut project, args)?,
        "aar" => aar::load_aar(&bytes, &mut project, args)?,
        "apk" | "aab" | "xapk" | "zip" | "apks" => apk::load_apk(&bytes, &mut project, args)?,
        _ => {
            // Sniff: DEX magic, ZIP magic, or classfile magic.
            if bytes.starts_with(b"dex\n") {
                dex::load_dex(&bytes, &mut project)?;
            } else if bytes.starts_with(b"PK") {
                apk::load_apk(&bytes, &mut project, args)?;
            } else if bytes.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
                if let Ok(jc) = JvmClass::parse(&bytes) {
                    project.jvm_classes.push(jc);
                }
            } else {
                anyhow::bail!("unrecognised input format: {}", path.display());
            }
        }
    }

    Ok(project)
}

/// Read every file entry out of a ZIP container.
pub fn read_zip(bytes: &[u8]) -> anyhow::Result<Vec<RawFile>> {
    let reader = Cursor::new(bytes.to_vec());
    let mut archive = zip::ZipArchive::new(reader).context("opening zip container")?;
    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        if !entry.is_file() {
            continue;
        }
        let name = entry.name().to_string();
        let mut data = Vec::new();
        if entry.read_to_end(&mut data).is_ok() {
            files.push(RawFile { name, data });
        }
    }
    Ok(files)
}

/// Decode the manifest + resources commonly found in APK/AAR containers.
pub(crate) fn absorb_android_resources(project: &mut LoadedProject) {
    if let Some(mf) = project.raw_files.iter().find(|f| {
        f.name == "AndroidManifest.xml" || f.name.ends_with("/AndroidManifest.xml")
    }) {
        if let Ok(doc) = AxmlDocument::decode(&mf.data) {
            project.manifest_info = Some(ManifestInfo::from_document(&doc));
            project.manifest = Some(doc);
        }
    }
    if let Some(rf) = project
        .raw_files
        .iter()
        .find(|f| f.name == "resources.arsc" || f.name.ends_with("/resources.arsc"))
    {
        if let Ok(arsc) = Arsc::parse(&rf.data) {
            project.resources = Some(arsc);
        }
    }
}
