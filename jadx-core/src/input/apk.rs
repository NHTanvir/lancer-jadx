//! `.apk` / `.aab` / `.xapk` / `.zip` loading.

use super::{absorb_android_resources, read_zip, LoadedProject};
use crate::args::JadxArgs;

pub fn load_apk(bytes: &[u8], project: &mut LoadedProject, args: &JadxArgs) -> anyhow::Result<()> {
    let files = read_zip(bytes)?;

    // Nested APKs (xapk / .apks bundles): recurse into contained apks.
    let nested_apks: Vec<Vec<u8>> = files
        .iter()
        .filter(|f| f.name.ends_with(".apk"))
        .map(|f| f.data.clone())
        .collect();

    for f in &files {
        // classes.dex, classes2.dex, ... and AAB base/*/dex/*.dex
        if f.name.ends_with(".dex") {
            let _ = super::dex::load_dex(&f.data, project);
        } else if f.name == "classes.jar" || f.name.ends_with("/classes.jar") {
            let _ = super::jar::load_jar(&f.data, project, args);
        }
    }

    project.raw_files = files;
    absorb_android_resources(project);

    for apk in nested_apks {
        let mut sub = LoadedProject::default();
        if super::apk::load_apk(&apk, &mut sub, args).is_ok() {
            project.dex_files.extend(sub.dex_files);
            project.jvm_classes.extend(sub.jvm_classes);
            if project.manifest.is_none() {
                project.manifest = sub.manifest;
                project.manifest_info = sub.manifest_info;
            }
            if project.resources.is_none() {
                project.resources = sub.resources;
            }
        }
    }

    Ok(())
}
