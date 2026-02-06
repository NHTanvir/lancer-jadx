//! `.aar` (Android library archive) loading.
//!
//! An AAR is a ZIP containing `classes.jar`, `AndroidManifest.xml`, `res/`,
//! and optionally `*.dex` / `R.txt`.

use super::{absorb_android_resources, read_zip, LoadedProject, RawFile};
use crate::args::JadxArgs;

pub fn load_aar(bytes: &[u8], project: &mut LoadedProject, args: &JadxArgs) -> anyhow::Result<()> {
    let files = read_zip(bytes)?;
    for f in &files {
        if f.name == "classes.jar" || f.name.ends_with("/classes.jar") {
            let _ = super::jar::load_jar(&f.data, project, args);
        } else if f.name.ends_with(".dex") {
            let _ = super::dex::load_dex(&f.data, project);
        }
    }
    project.raw_files = files.into_iter().collect::<Vec<RawFile>>();
    absorb_android_resources(project);
    Ok(())
}
