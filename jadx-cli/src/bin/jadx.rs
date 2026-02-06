//! `jadx` — upstream-compatible compatibility binary. Drop-in for existing
//! jadx wrappers; delegates to the shared `jadx_cli` surface.

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    if let Err(e) = jadx_cli::run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
