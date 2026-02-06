//! `.jar` (and embedded `classes.jar`) loading → JVM classes.

use super::{read_zip, JvmClass, LoadedProject};
use crate::args::JadxArgs;

pub fn load_jar(bytes: &[u8], project: &mut LoadedProject, _args: &JadxArgs) -> anyhow::Result<()> {
    let files = read_zip(bytes)?;
    load_classes_from(&files, project);
    // A jar may also ship resources / a manifest.
    for f in &files {
        if f.name.ends_with(".dex") {
            let _ = super::dex::load_dex(&f.data, project);
        }
    }
    Ok(())
}

/// Parse every `.class` entry from a set of raw files into the project.
pub fn load_classes_from(files: &[super::RawFile], project: &mut LoadedProject) {
    for f in files {
        if f.name.ends_with(".class") {
            match JvmClass::parse(&f.data) {
                Ok(jc) => project.jvm_classes.push(jc),
                Err(e) => tracing::debug!("skip {}: {e}", f.name),
            }
        }
    }
}
