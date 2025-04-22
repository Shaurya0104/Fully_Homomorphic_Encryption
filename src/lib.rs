//! FHE-AES Library
//!
//! This crate provides fully homomorphic AES-128 encryption using boolean circuits and TFHE.

pub mod utils;
pub mod circuit;
pub mod gate;
pub mod fhe_aes;

pub use fhe_aes::{BoolFheAes, encrypt_reference_aes128};
