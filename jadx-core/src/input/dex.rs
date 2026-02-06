//! Standalone `.dex` / `.odex` loading, including the multi-DEX container format.

use super::LoadedProject;
use jadx_dex::{find_dex_headers, DexFile};

/// Parse one or more DEX images out of a buffer. Supports both classic
/// single-image `.dex` and the Android 14+ single-file container (which packs
/// several DEX headers into one file).
pub fn load_dex(bytes: &[u8], project: &mut LoadedProject) -> anyhow::Result<()> {
    let offsets = find_dex_headers(bytes);
    let mut loaded = 0;
    for off in offsets {
        match DexFile::parse(bytes, off) {
            Ok(df) => {
                project.dex_files.push(df);
                loaded += 1;
            }
            Err(e) => {
                tracing::warn!("failed to parse DEX at offset {off}: {e}");
            }
        }
    }
    if loaded == 0 {
        anyhow::bail!("no DEX images could be parsed");
    }
    Ok(())
}
