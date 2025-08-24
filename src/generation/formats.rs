use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize)]
pub enum Format {
    /// Markdown output
    Markdown,
    /// Plain text output
    Plain,
    /// JSON structured output
    Json,
}
