#![forbid(unsafe_code)]

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "omnisstream")]
struct Args {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,omnisstream=info".to_string()),
        )
        .init();

    let _args = Args::parse();
    let version = omnisstream::hashing::version();
    anyhow::ensure!(!version.is_empty(), "version must not be empty");
    Ok(())
}
