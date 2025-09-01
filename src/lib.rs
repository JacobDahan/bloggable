pub mod cli;
pub mod generation;
pub mod git;

// Re-export main types for library users
pub use generation::{Format, Medium, Voice};
