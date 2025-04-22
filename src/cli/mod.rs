//! Command-line interface module for FHE-AES operations

mod commands;
pub use commands::AesCommand;

use crate::error::AesError;
use clap::Parser;
use log::info;

/// CLI entry point handler
pub fn run_cli() -> Result<(), AesError> {
    let command = AesCommand::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    match command {
        AesCommand::Encrypt {
            key,
            iv,
            count,
        } => commands::handle_encrypt(key, iv, count),
        AesCommand::Benchmark {
            iterations,
        } => commands::handle_benchmark(iterations),
        AesCommand::Verify {
            samples,
        } => commands::handle_verify(samples),
    }
}
