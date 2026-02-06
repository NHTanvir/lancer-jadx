//! lancer-jadx
//! Rust clone of jadx. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-jadx", version, about = "Rust clone of jadx")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-jadx - scaffold ready. Implement per plan.md.");
    Ok(())
}
