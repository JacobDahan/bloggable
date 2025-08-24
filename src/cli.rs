pub mod args;
pub mod commands;

pub use args::Cli;

pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    println!("Running with CLI args: {:?}", cli);
    Ok(())
}
