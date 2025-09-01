use bloggable::cli::{Cli, run};
use clap::Parser;
use human_panic::setup_panic;
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Panic gracefully with a human-friendly message and a report file.
    setup_panic!();

    // Initialize tracing for logging
    let _guard = init();

    // Parse command line arguments
    let cli = Cli::parse();

    // And let the magic happen...
    match run(cli).await {
        Ok(_) => std::process::exit(exitcode::OK),
        Err(err) => {
            // TODO: Return proper exit codes based on error type
            eprintln!("Error: {}", err);
            std::process::exit(exitcode::SOFTWARE);
        }
    }
}

fn init() -> tracing_appender::non_blocking::WorkerGuard {
    let (non_blocking, guard) = tracing_appender::non_blocking(std::io::stdout());

    // Use cfg! to select log level depending on build profile
    let subscriber = FmtSubscriber::builder()
        .with_max_level(if cfg!(debug_assertions) {
            tracing::Level::DEBUG // Debug builds
        } else {
            tracing::Level::ERROR // Release builds
        })
        .with_writer(non_blocking)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    guard
}
