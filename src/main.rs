use bloggable::cli::{Cli, run};
use clap::Parser;
use human_panic::setup_panic;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Panic gracefully with a human-friendly message and a report file.
    setup_panic!();

    let cli = Cli::parse();

    match run(cli).await {
        Ok(_) => std::process::exit(exitcode::OK),
        Err(err) => {
            // TODO: Return proper exit codes based on error type
            eprintln!("Error: {}", err);
            std::process::exit(exitcode::SOFTWARE);
        }
    }
}
