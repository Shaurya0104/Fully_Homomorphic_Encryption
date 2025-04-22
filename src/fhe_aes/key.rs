//! Key management and encryption/decryption operations

use super::*;
use bit_vec::BitVec;
use tfhe::boolean::prelude::*;
use crate::utils::constants::{
    AES_128_KEY_SIZE, AES_128_KEY_SIZE_BITS,
    AES_BLOCK_SIZE, AES_BLOCK_SIZE_BITS,
    AES_128_OUTPUT_BITSIZE
};


impl BoolFheAes {
    /// Encrypts AES-128 key using client key
    pub fn encrypt_key(
        client_key: &ClientKey,
        key: &[u8; AES_128_KEY_SIZE],
    ) -> [Ciphertext; AES_128_KEY_SIZE_BITS] {
        let key_bits = BitVec::from_bytes(key);
        let mut encrypted = std::array::from_fn(|_| Ciphertext::Trivial(false));
        
        for (i, bit) in key_bits.iter().rev().enumerate() {
            encrypted[i] = client_key.encrypt(bit);
        }
        encrypted
    }

    /// Encrypts initialization vector
    pub fn encrypt_iv(
        client_key: &ClientKey,
        block: &[u8; AES_BLOCK_SIZE],
    ) -> [Ciphertext; AES_BLOCK_SIZE_BITS] {
        let block_bits = BitVec::from_bytes(block);
        let mut encrypted = std::array::from_fn(|_| Ciphertext::Trivial(false));
        
        for (i, bit) in block_bits.iter().rev().enumerate() {
            encrypted[i] = client_key.encrypt(bit);
        }
        encrypted
    }

    /// Decrypts output block
    pub fn decrypt_output(
        client_key: &ClientKey,
        output: &[Ciphertext; AES_128_OUTPUT_BITSIZE],
    ) -> [u8; AES_BLOCK_SIZE] {
        let mut bits = BitVec::with_capacity(128);
        for ct in output.iter().rev() {
            bits.push(client_key.decrypt(ct));
        }
        bits.to_bytes().try_into().unwrap()
    }

    /// Expands the encrypted key
    pub fn expand_key(&self, key: [Ciphertext; AES_128_KEY_SIZE_BITS]) {
        self.expanded_key_outputs.clear();
        for (i, ct) in key.iter().enumerate() {
            self.expanded_key_outputs.insert(i as u32, ct.clone());
        }
        self.execute_all(&self.expanded_key_outputs, true);
    }
}
