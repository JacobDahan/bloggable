use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, ValueEnum, Serialize, Deserialize)]
pub enum Voice {
    /// Educational, beginner-friendly explanations
    Educational,
    /// Deep technical analysis with implementation details
    Technical,
    /// Fun, engaging, personality-driven writing
    Playful,
    /// Brief, to-the-point explanations
    Concise,
}
