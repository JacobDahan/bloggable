use crate::generation::{Format, Medium, Voice};
use clap::Subcommand;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a blog post from commits (default command)
    Generate {
        /// Use specific config file
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Git commit range (e.g., HEAD~5..HEAD, v1.0..v1.1)
        #[arg(long, short = 'c', value_name = "RANGE")]
        commits: String,

        /// Writing voice
        #[arg(long, short = 'v', value_enum, default_value_t = Voice::Educational)]
        voice: Voice,

        /// Target medium for the post
        #[arg(long, short = 'm', value_enum, default_value_t = Medium::Blog)]
        medium: Medium,

        /// Specific focus or goal for the post
        #[arg(long, short = 'i', value_name = "TEXT")]
        intent: Option<String>,

        /// Save to file instead of stdout
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output format
        #[arg(long, short = 'f', value_enum, default_value_t = Format::Markdown)]
        format: Format,

        /// Show prioritized context for the commit range without generating post
        #[arg(long = "dry-run")]
        dry_run: bool,
        // TODO: Add option for setting max turns for generation
        // TODO: Add option for setting max tokens for context size
        // TODO: Add option for setting API key, provider for this run
    },
    /// Initialize configuration file
    Init {
        // TODO: Add option for setting default voice, medium, format in config
        // TODO: Add option for setting max turns for generation in config
        // TODO: Add option for setting max tokens for context size in config
        // TODO: Add option for setting API key, provider for config
    },
    /// List available voices and mediums
    List {
        /// List voices
        #[arg(long)]
        voices: bool,
        /// List mediums
        #[arg(long)]
        mediums: bool,
    },
}
