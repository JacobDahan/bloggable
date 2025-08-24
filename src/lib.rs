pub mod cli;
pub mod generation;

// Re-export main types for library users
pub use generation::{Format, Medium, Voice};