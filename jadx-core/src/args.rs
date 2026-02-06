//! Decompiler options — the full upstream `jadx` flag surface plus Lancer extras.
//!
//! `jadx-cli` and the GUI both build a `JadxArgs` and hand it to the
//! [`crate::Jadx`] orchestrator, so every flag has a home here.

use std::path::PathBuf;

/// Which identifiers the deobfuscator/renamer is allowed to rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RenameFlags {
    None,
    #[default]
    All,
    Case,
    Valid,
    Printable,
}

/// Output source language / container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Java,
    Json,
}

/// Which external decompiler backend to mirror for the JVM-bytecode path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DecompilerBackend {
    #[default]
    Jadx,
    Vineflower,
    Cfr,
}

#[derive(Debug, Clone)]
pub struct JadxArgs {
    pub inputs: Vec<PathBuf>,
    pub output_dir: PathBuf,

    // --- source / resource toggles ---
    pub no_src: bool,
    pub no_res: bool,
    pub decode_resources: bool,
    pub single_class: Option<String>,
    pub single_class_output: Option<PathBuf>,
    pub output_format: OutputFormat,

    // --- code rendering ---
    pub show_bad_code: bool,
    pub no_imports: bool,
    pub no_debug_info: bool,
    pub add_debug_lines: bool,
    pub no_inline_anonymous: bool,
    pub no_inline_methods: bool,
    pub no_replace_consts: bool,
    pub escape_unicode: bool,
    pub respect_bytecode_access_modifiers: bool,
    pub fs_case_sensitive: bool,

    // --- deobfuscation ---
    pub deobf: bool,
    pub deobf_min: u32,
    pub deobf_max: u32,
    pub deobf_rewrite_cfg: bool,
    pub deobf_use_sourcename: bool,
    pub rename_flags: RenameFlags,

    // --- languages / plugins ---
    pub kotlin: bool,
    pub plugin_decompiler: DecompilerBackend,
    pub plugins_options: Vec<(String, String)>,

    // --- diagnostics / graphs ---
    pub cfg: bool,
    pub raw_cfg: bool,
    pub export_gradle: bool,
    pub use_dx: bool,

    // --- runtime ---
    pub threads_count: usize,
    pub verbose: bool,
    pub quiet: bool,

    // --- Lancer extras ---
    pub ai_rename: bool,
}

impl Default for JadxArgs {
    fn default() -> Self {
        JadxArgs {
            inputs: Vec::new(),
            output_dir: PathBuf::from("jadx-output"),
            no_src: false,
            no_res: false,
            decode_resources: true,
            single_class: None,
            single_class_output: None,
            output_format: OutputFormat::Java,
            show_bad_code: false,
            no_imports: false,
            no_debug_info: false,
            add_debug_lines: false,
            no_inline_anonymous: false,
            no_inline_methods: false,
            no_replace_consts: false,
            escape_unicode: false,
            respect_bytecode_access_modifiers: false,
            fs_case_sensitive: false,
            deobf: false,
            deobf_min: 3,
            deobf_max: 64,
            deobf_rewrite_cfg: false,
            deobf_use_sourcename: false,
            rename_flags: RenameFlags::All,
            kotlin: false,
            plugin_decompiler: DecompilerBackend::Jadx,
            plugins_options: Vec::new(),
            cfg: false,
            raw_cfg: false,
            export_gradle: false,
            use_dx: false,
            threads_count: 0, // 0 = auto (rayon default)
            verbose: false,
            quiet: false,
            ai_rename: false,
        }
    }
}
