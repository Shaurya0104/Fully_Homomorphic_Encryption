//! Command-line interface module for FHE-AES operations

mod commands;
use clap::{Parser, Subcommand, Args};
use anyhow::Result;
#[derive(Parser)]
#[command(name = "fhe-aes")]
#[command(about = "FHE AES Implementation", version, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt data using FHE-AES
    Encrypt(commands::EncryptArgs),
    
    /// Benchmark FHE operations
    Benchmark(commands::BenchmarkArgs),
    
    /// Verify against reference implementation
    Verify(commands::VerifyArgs),
}

pub fn run() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match cli.command {
        Commands::Encrypt(args) => commands::handle_encrypt(args),
        Commands::Benchmark(args) => commands::handle_benchmark(args),
        Commands::Verify(args) => commands::handle_verify(args),
    }
}
