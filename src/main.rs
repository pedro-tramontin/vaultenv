use clap::Parser;
use vaultenv::config::Options;

#[tokio::main]
async fn main() {
    let opts = Options::parse();

    // Just dump config until the orchestration is wired in later phases.
    eprintln!("{opts:#?}");
    std::process::exit(1);
}
