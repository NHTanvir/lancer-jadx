//! lancer-jadx — native GUI by default; full CLI surface behind `--cli`.
//!
//! * `lancer-jadx`                 → opens the GUI window (Lancer-standard).
//! * `lancer-jadx --cli <args…>`   → falls through to the `jadx-cli` surface.
//! * `lancer-jadx <subcommand> …`  → also routed to the CLI (decompile, find,
//!   findings, tree, extract-strings, extract-manifest, serve, lsp, self-test).
//!
//! For CI / headless / scripting, always pass `--cli` (or a subcommand).

#[cfg(feature = "gui")]
mod http_server;

#[cfg(feature = "gui")]
mod gui;

use std::process::ExitCode;

fn main() -> ExitCode {
    init_tracing();

    let raw: Vec<String> = std::env::args().collect();
    let prog = raw.first().cloned().unwrap_or_else(|| "lancer-jadx".to_string());
    let rest = &raw[1..];

    // Explicit CLI passthrough: strip the leading `--cli` token.
    if let Some(first) = rest.first() {
        if first == "--cli" {
            let mut argv = vec![prog];
            argv.extend_from_slice(&rest[1..]);
            return run_cli(argv);
        }
        // Any other arguments → treat as the CLI surface (a subcommand or input).
        let mut argv = vec![prog];
        argv.extend_from_slice(rest);
        return run_cli(argv);
    }

    // No arguments → launch the GUI.
    launch_gui()
}

fn run_cli(argv: Vec<String>) -> ExitCode {
    match jadx_cli::run_from(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(feature = "gui")]
fn launch_gui() -> ExitCode {
    match gui::launch() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "gui"))]
fn launch_gui() -> ExitCode {
    eprintln!(
        "lancer-jadx was built without the GUI feature.\n\
         Run with `--cli` and a subcommand, e.g.:\n\
         \tlancer-jadx --cli decompile app.apk -d out/\n\
         \tlancer-jadx --cli findings app.apk --sarif"
    );
    ExitCode::FAILURE
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
