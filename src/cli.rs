pub mod args;
pub mod commands;

pub use args::Cli;
pub use clap::{CommandFactory, Parser};

use crate::git::{parsing::CommitParser, repository::Repository};

use tracing::{debug, info};

/// The main entry point for bloggable CLI operations.
pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Some(commands::Command::Generate { commits, .. }) => {
            info!("Generating blog post for commits {commits}...");

            // TODO: Allow setting repository path and type via CLI options
            let current_dir = std::env::current_dir()?;

            debug!(
                "Using current directory as repository path: {}",
                current_dir.display()
            );

            // First, validate and open the repository
            let repository = Repository::try_local(current_dir).await?;

            let repository = std::sync::Arc::new(tokio::sync::RwLock::new(repository));
            let parser = CommitParser::new(repository);

            // Next, parse the commit range
            let commit_spec = parser.parse_commits(&commits).await?;

            // ... and generate diffs for the parsed commits
            let diffs = parser.generate_diffs(commit_spec).await?;

            debug!("Generated {} diffs for processing", diffs.len());

            // At this point, we have a valid repository and a list of diffs to process,
            // so we have effectively completed all of the logic that is owned by the CLI module.

            // Now, hand off to the core logic to generate the blog post.
            debug!("--------------- TODO: Hand off to core logic ---------------");

            Ok(())
        }
        Some(commands::Command::Init { .. }) => {
            // Handle Init command
            info!("Initializing configuration...");
            debug!("--------------- TODO: Implement init logic ---------------");
            Ok(())
        }
        Some(commands::Command::List { .. }) => {
            // Handle List command
            info!("Listing available voices and mediums...");
            debug!("--------------- TODO: Implement listing logic ---------------");
            Ok(())
        }
        None => {
            // If no command is provided, show help
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}
