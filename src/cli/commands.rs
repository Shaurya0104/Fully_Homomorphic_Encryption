//! Command implementations for FHE-AES operations

use super::*;
use crate::{
    bool_fhe_aes::BoolFheAes,
    encrypt_reference_aes128,
    utils::constants::{AES_128_KEY_SIZE, AES_BLOCK_SIZE},
};
use clap::Subcommand;
use std::time::Instant;
use tfhe::boolean::prelude::*;

/// Main CLI command structure
#[derive(Subcommand)]
pub enum AesCommand {
    /// Encrypt data using FHE-AES
    Encrypt {
        #[clap(short, long, help = "Encryption key in hex format")]
        key: String,
        
        #[clap(short, long, help = "Initialization vector in hex format")]
        iv: String,
        
        #[clap(short, long, help = "Number of blocks to encrypt")]
        count: usize,
    },
    
    /// Benchmark FHE operations
    Benchmark {
        #[clap(short, long, help = "Number of iterations for benchmarking")]
        iterations: usize,
    },
    
    /// Verify against reference implementation
    Verify {
        #[clap(short, long, help = "Number of test samples to verify")]
        samples: usize,
    },
}

/// Handle encryption command
pub fn handle_encrypt(key: String, iv: String, count: usize) -> Result<(), AesError> {
    let (key_bytes, iv_bytes) = parse_inputs(&key, &iv)?;
    
    info!("Starting FHE-AES encryption with {} blocks", count);
    let (client_key, server_key) = gen_keys();
    
    let fhe_aes = BoolFheAes::new(server_key);
    let fhe_key = BoolFheAes::encrypt_key(&client_key, &key_bytes);
    let fhe_iv = BoolFheAes::encrypt_iv(&client_key, &iv_bytes);
    
    let start_time = Instant::now();
    fhe_aes.expand_key(fhe_key);
    let key_expansion_time = start_time.elapsed();
    
    let encrypt_start = Instant::now();
    let outputs = fhe_aes.aes_ctr_blocks(fhe_iv, count);
    let encrypt_time = encrypt_start.elapsed();
    
    info!("Key expansion time: {:?}", key_expansion_time);
    info!("Encryption time for {} blocks: {:?}", count, encrypt_time);
    
    Ok(())
}

/// Handle benchmark command
pub fn handle_benchmark(iterations: usize) -> Result<(), AesError> {
    info!("Starting benchmarking with {} iterations", iterations);
    // Benchmarking implementation
    Ok(())
}

/// Handle verification command
pub fn handle_verify(samples: usize) -> Result<(), AesError> {
    info!("Starting verification with {} samples", samples);
    // Verification implementation
    Ok(())
}

/// Parse hexadecimal inputs into byte arrays
fn parse_inputs(key: &str, iv: &str) -> Result<([u8; AES_128_KEY_SIZE], [u8; AES_BLOCK_SIZE]), AesError
