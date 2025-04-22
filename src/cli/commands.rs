use clap::{Parser, Subcommand, Args};
use anyhow::{Context, Result};
use log::info;
use std::time::Instant;
use tfhe::boolean::prelude::*;
use crate::{
    BoolFheAes,
    encrypt_reference_aes128,
    utils::constants::{AES_128_KEY_SIZE, AES_BLOCK_SIZE}
};

#[derive(Args, Debug)]
pub struct EncryptArgs {
    #[arg(short, long)]
    key: String,
    
    #[arg(short, long)]
    iv: String,
    
    #[arg(short, long)]
    count: usize,
    
    #[arg(short, long)]
    slow: bool,
}

#[derive(Args, Debug)]
pub struct BenchmarkArgs {
    #[arg(short, long)]
    iterations: usize,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(short, long)]
    samples: usize,
}

pub fn handle_encrypt(args: EncryptArgs) -> Result<()> {
    let (key_bytes, iv_bytes) = parse_inputs(&args.key, &args.iv)
        .context("Failed to parse inputs")?;

    info!("Starting FHE-AES encryption with {} blocks", args.count);
    
    let (client_key, server_key) = tfhe::boolean::gen_keys();
    let fhe_aes = BoolFheAes::new(server_key);
    
    let fhe_key = BoolFheAes::encrypt_key(&client_key, &key_bytes);
    let fhe_iv = BoolFheAes::encrypt_iv(&client_key, &iv_bytes);

    // Key expansion
    let start_time = Instant::now();
    fhe_aes.expand_key(fhe_key);
    let key_expansion_time = start_time.elapsed();
    info!("Key expansion time: {:?}", key_expansion_time);

    // Encryption
    let encrypt_start = Instant::now();
    let outputs = fhe_aes.aes_ctr_blocks(fhe_iv, args.count);
    let encrypt_time = encrypt_start.elapsed();
    info!("Encryption time for {} blocks: {:?}", args.count, encrypt_time);

    // Verification
    let decrypted_outputs: Vec<[u8; AES_BLOCK_SIZE]> = outputs
        .iter()
        .map(|output| BoolFheAes::decrypt_output(&client_key, output))
        .collect();

    let iv = u128::from_be_bytes(iv_bytes);
    let ivs = (0..args.count)
        .map(|i| (iv + i as u128).to_be_bytes())
        .collect::<Vec<_>>();

    let expected_outputs = encrypt_reference_aes128(ivs, key_bytes);
    
    for (expected, actual) in expected_outputs.iter().zip(decrypted_outputs.iter()) {
        assert_eq!(
            expected.as_slice(),
            actual,
            "Mismatch between expected and actual output"
        );
    }

    info!("Successfully verified all {} blocks", args.count);
    Ok(())
}

pub fn handle_benchmark(args: BenchmarkArgs) -> Result<()> {
    info!("Starting benchmarking with {} iterations", args.iterations);
    // Benchmarking implementation
    Ok(())
}

pub fn handle_verify(args: VerifyArgs) -> Result<()> {
    info!("Starting verification with {} samples", args.samples);
    // Verification implementation
    Ok(())
}

fn parse_inputs(key: &str, iv: &str) -> Result<([u8; AES_128_KEY_SIZE], [u8; AES_BLOCK_SIZE])> {
    let key_bytes = hex::decode(key)
        .context("Failed to decode key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid key length"))?;

    let iv_bytes = hex::decode(iv)
        .context("Failed to decode IV")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid IV length"))?;

    Ok((key_bytes, iv_bytes))
}
