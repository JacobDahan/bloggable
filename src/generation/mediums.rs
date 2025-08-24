use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize)]
pub enum Medium {
    /// Full blog post format
    Blog,
    /// Professional release notes
    #[value(name = "release-notes")]
    ReleaseNotes,
    /// Twitter thread format
    #[value(name = "twitter-thread")]
    TwitterThread,
}
