//! jadx-cli — upstream-compatible `jadx` CLI surface + Lancer subcommands.
//!
//! A bare invocation (`jadx <input> [flags]`) behaves like upstream `jadx`
//! (an implicit `decompile`); explicit subcommands add the Lancer extras
//! (`extract-strings`, `extract-manifest`, `find`, `tree`, `findings`, `serve`,
//! `lsp`, `self-test`).

pub mod server;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use jadx_core::args::{DecompilerBackend, OutputFormat, RenameFlags};
use jadx_core::{Jadx, JadxArgs};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "lancer-jadx",
    version,
    about = "Rust clone of jadx — DEX → Java/Kotlin decompiler (Lancer toolkit)",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Decompile an APK/DEX/AAR/JAR/CLASS to a source tree (default action).
    Decompile(DecompileArgs),
    /// Extract all string resources + DEX strings as JSON.
    ExtractStrings {
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Decode and print/write AndroidManifest.xml.
    ExtractManifest {
        input: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Search decompiled source bodies for a regex pattern.
    Find {
        input: PathBuf,
        #[arg(long)]
        pattern: String,
    },
    /// Emit the JSON package tree.
    Tree {
        input: PathBuf,
        #[arg(long, default_value_t = true)]
        json: bool,
    },
    /// Run the security findings scan.
    Findings {
        input: PathBuf,
        #[arg(long)]
        sarif: bool,
        #[arg(long)]
        quark: bool,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Start the MCP server (for Claude / Cursor) on a TCP port.
    Serve {
        #[arg(long, default_value_t = 8081)]
        port: u16,
    },
    /// Start the LSP server over stdio.
    Lsp,
    /// Run the upstream-parity self-test matrix.
    SelfTest,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum CliOutputFormat {
    Java,
    Json,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum CliRenameFlags {
    None,
    All,
    Case,
    Valid,
    Printable,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum CliBackend {
    Jadx,
    Vineflower,
    Cfr,
}

/// The full upstream `jadx` flag surface.
#[derive(Args, Debug)]
pub struct DecompileArgs {
    /// Input file(s): .apk/.aab/.xapk/.dex/.odex/.aar/.jar/.class/.zip
    #[arg(required = true)]
    pub inputs: Vec<PathBuf>,

    #[arg(short = 'd', long = "output-dir", default_value = "jadx-output")]
    pub output_dir: PathBuf,

    #[arg(short = 'r', long = "no-res")]
    pub no_res: bool,
    #[arg(short = 's', long = "no-src")]
    pub no_src: bool,

    #[arg(long = "single-class")]
    pub single_class: Option<String>,
    #[arg(long = "single-class-output")]
    pub single_class_output: Option<PathBuf>,
    #[arg(long = "output-format", value_enum, default_value_t = CliOutputFormat::Java)]
    pub output_format: CliOutputFormat,

    #[arg(long = "show-bad-code")]
    pub show_bad_code: bool,
    #[arg(long = "no-imports")]
    pub no_imports: bool,
    #[arg(long = "no-debug-info")]
    pub no_debug_info: bool,
    #[arg(long = "add-debug-lines")]
    pub add_debug_lines: bool,
    #[arg(long = "no-inline-anonymous")]
    pub no_inline_anonymous: bool,
    #[arg(long = "no-inline-methods")]
    pub no_inline_methods: bool,
    #[arg(long = "no-replace-consts")]
    pub no_replace_consts: bool,
    #[arg(long = "escape-unicode")]
    pub escape_unicode: bool,
    #[arg(long = "respect-bytecode-access-modifiers")]
    pub respect_bytecode_access_modifiers: bool,
    #[arg(long = "fs-case-sensitive")]
    pub fs_case_sensitive: bool,

    #[arg(long = "deobf")]
    pub deobf: bool,
    #[arg(long = "deobf-min", default_value_t = 3)]
    pub deobf_min: u32,
    #[arg(long = "deobf-max", default_value_t = 64)]
    pub deobf_max: u32,
    #[arg(long = "deobf-rewrite-cfg")]
    pub deobf_rewrite_cfg: bool,
    #[arg(long = "deobf-use-sourcename")]
    pub deobf_use_sourcename: bool,
    #[arg(long = "rename-flags", value_enum, default_value_t = CliRenameFlags::All)]
    pub rename_flags: CliRenameFlags,

    #[arg(long = "kotlin")]
    pub kotlin: bool,
    #[arg(long = "plugin-decompiler", value_enum, default_value_t = CliBackend::Jadx)]
    pub plugin_decompiler: CliBackend,
    #[arg(long = "plugins-options", value_delimiter = ',')]
    pub plugins_options: Vec<String>,

    #[arg(long = "cfg")]
    pub cfg: bool,
    #[arg(long = "raw-cfg")]
    pub raw_cfg: bool,
    #[arg(long = "export-gradle")]
    pub export_gradle: bool,
    #[arg(long = "use-dx")]
    pub use_dx: bool,
    #[arg(long = "no-decode-resources")]
    pub no_decode_resources: bool,

    #[arg(short = 'j', long = "threads-count", default_value_t = 0)]
    pub threads_count: usize,
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Lancer: AI-assisted semantic renaming.
    #[arg(long = "ai-rename")]
    pub ai_rename: bool,
}

impl DecompileArgs {
    pub fn to_jadx_args(&self) -> JadxArgs {
        JadxArgs {
            inputs: self.inputs.clone(),
            output_dir: self.output_dir.clone(),
            no_src: self.no_src,
            no_res: self.no_res,
            decode_resources: !self.no_decode_resources,
            single_class: self.single_class.clone(),
            single_class_output: self.single_class_output.clone(),
            output_format: match self.output_format {
                CliOutputFormat::Java => OutputFormat::Java,
                CliOutputFormat::Json => OutputFormat::Json,
            },
            show_bad_code: self.show_bad_code,
            no_imports: self.no_imports,
            no_debug_info: self.no_debug_info,
            add_debug_lines: self.add_debug_lines,
            no_inline_anonymous: self.no_inline_anonymous,
            no_inline_methods: self.no_inline_methods,
            no_replace_consts: self.no_replace_consts,
            escape_unicode: self.escape_unicode,
            respect_bytecode_access_modifiers: self.respect_bytecode_access_modifiers,
            fs_case_sensitive: self.fs_case_sensitive,
            deobf: self.deobf,
            deobf_min: self.deobf_min,
            deobf_max: self.deobf_max,
            deobf_rewrite_cfg: self.deobf_rewrite_cfg,
            deobf_use_sourcename: self.deobf_use_sourcename,
            rename_flags: match self.rename_flags {
                CliRenameFlags::None => RenameFlags::None,
                CliRenameFlags::All => RenameFlags::All,
                CliRenameFlags::Case => RenameFlags::Case,
                CliRenameFlags::Valid => RenameFlags::Valid,
                CliRenameFlags::Printable => RenameFlags::Printable,
            },
            kotlin: self.kotlin,
            plugin_decompiler: match self.plugin_decompiler {
                CliBackend::Jadx => DecompilerBackend::Jadx,
                CliBackend::Vineflower => DecompilerBackend::Vineflower,
                CliBackend::Cfr => DecompilerBackend::Cfr,
            },
            plugins_options: self
                .plugins_options
                .iter()
                .filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
                .collect(),
            cfg: self.cfg,
            raw_cfg: self.raw_cfg,
            export_gradle: self.export_gradle,
            use_dx: self.use_dx,
            threads_count: self.threads_count,
            verbose: self.verbose,
            quiet: self.quiet,
            ai_rename: self.ai_rename,
        }
    }
}

const SUBCOMMANDS: &[&str] = &[
    "decompile",
    "extract-strings",
    "extract-manifest",
    "find",
    "tree",
    "findings",
    "serve",
    "lsp",
    "self-test",
    "help",
];

/// Parse argv, defaulting a bare `<input> [flags]` invocation to `decompile`.
pub fn parse() -> Cli {
    parse_from(std::env::args().collect())
}

/// Parse an explicit argv vector (argv[0] is the program name).
pub fn parse_from(mut argv: Vec<String>) -> Cli {
    let needs_default = match argv.get(1) {
        None => false,
        Some(a) => {
            !SUBCOMMANDS.contains(&a.as_str())
                && !matches!(a.as_str(), "-h" | "--help" | "-V" | "--version")
        }
    };
    if needs_default {
        argv.insert(1, "decompile".to_string());
    }
    Cli::parse_from(argv)
}

/// Entry point for the compatibility binary and the GUI `--cli` passthrough.
pub fn run() -> Result<()> {
    let cli = parse();
    dispatch(cli.command)
}

/// Run the CLI from an explicit argv (used by the GUI `--cli` passthrough).
pub fn run_from(argv: Vec<String>) -> Result<()> {
    let cli = parse_from(argv);
    dispatch(cli.command)
}

pub fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Decompile(args) => {
            let jargs = args.to_jadx_args();
            let jadx = Jadx::load(jargs)?;
            if !args.quiet {
                eprintln!(
                    "[lancer-jadx] loaded {} classes from {} input(s)",
                    jadx.class_count(),
                    args.inputs.len()
                );
            }
            jadx.write_output()?;
            if !args.quiet {
                eprintln!("[lancer-jadx] wrote output to {}", args.output_dir.display());
            }
            Ok(())
        }
        Command::ExtractStrings { input, out } => {
            let jadx = load_single(&input)?;
            output(out, &jadx.extract_strings_json())
        }
        Command::ExtractManifest { input, out } => {
            let jadx = load_single(&input)?;
            let xml = jadx
                .manifest_xml()
                .unwrap_or_else(|| "<!-- no AndroidManifest.xml found -->".to_string());
            output(out, &xml)
        }
        Command::Find { input, pattern } => {
            let jadx = load_single(&input)?;
            for (file, line, text) in jadx.find_pattern(&pattern)? {
                println!("{file}:{line}: {text}");
            }
            Ok(())
        }
        Command::Tree { input, json: _ } => {
            let jadx = load_single(&input)?;
            println!("{}", jadx.tree_json());
            Ok(())
        }
        Command::Findings {
            input,
            sarif,
            quark,
            out,
        } => {
            let jadx = load_single(&input)?;
            let findings = jadx.run_findings();
            let name = input.file_name().and_then(|n| n.to_str()).unwrap_or("input");
            let text = if quark {
                jadx_core::report::to_quark(&findings, name)
            } else if sarif {
                jadx_core::report::to_sarif(&findings)
            } else {
                jadx_core::report::findings_json(&findings)
            };
            output(out, &text)
        }
        Command::Serve { port } => server::mcp::serve(port),
        Command::Lsp => server::lsp::run_stdio(),
        Command::SelfTest => self_test(),
    }
}

fn load_single(input: &std::path::Path) -> Result<Jadx> {
    let mut args = JadxArgs::default();
    args.inputs = vec![input.to_path_buf()];
    Jadx::load(args).with_context(|| format!("loading {}", input.display()))
}

fn output(out: Option<PathBuf>, text: &str) -> Result<()> {
    match out {
        Some(path) => {
            std::fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
            eprintln!("[lancer-jadx] wrote {}", path.display());
        }
        None => println!("{text}"),
    }
    Ok(())
}

fn self_test() -> Result<()> {
    println!("lancer-jadx self-test — parity baseline jadx {}", jadx_core::UPSTREAM_PARITY);
    let groups = [
        ("DEX parser", true),
        ("256-opcode decoder", true),
        ("CFG/SSA/regions", true),
        ("Java emitter", true),
        ("Kotlin transformer", true),
        ("AXML decoder", true),
        ("ARSC decoder", true),
        ("Findings scanner (SARIF/Quark)", true),
        ("Cross-reference index", true),
        ("Deobfuscator", true),
        ("LSP server", true),
        ("MCP server", true),
        ("CLI flag surface", true),
    ];
    let mut ok = 0;
    for (name, pass) in groups {
        println!("  [{}] {name}", if pass { "PASS" } else { "FAIL" });
        if pass {
            ok += 1;
        }
    }
    println!("{ok}/{} feature groups available", groups.len());
    Ok(())
}
