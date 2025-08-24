use crate::cli::commands::Command;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "bloggable")]
#[command(about = "Transform git commits into engaging content with one command")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Verbose output
    #[arg(long, short)]
    pub verbose: bool,
}
