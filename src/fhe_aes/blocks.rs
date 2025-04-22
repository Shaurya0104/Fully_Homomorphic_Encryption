//! Block processing and CTR mode implementation

use super::*;
use crate::utils::constants::{AES_BLOCK_SIZE_BITS, AES_128_OUTPUT_BITSIZE};
use bit_vec::BitVec;
use dashmap::DashMap;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;

impl BoolFheAes {
    /// FHE-computes a single AES-128 block for the encrypted AES-128 `block` using the expanded key.
    /// It then extracts and returns the FHE-encrypted output block.
    /// NOTE: assumes the key was already expanded using `expand_key`
    pub fn execute(
        &self,
        block: [Ciphertext; AES_BLOCK_SIZE_BITS],
    ) -> [Ciphertext; AES_128_OUTPUT_BITSIZE] {
        let values = DashMap::with_capacity(self.output_end as usize);
        
        // Insert input block into values map
        block.into_par_iter().enumerate().for_each(|(i, input)| {
            let wire_index = (AES_128_OUTPUT_BITSIZE + i) as u32;
            values.insert(wire_index, input);
        });

        // Execute all relevant gates
        self.execute_all(&values, false);

        // Extract output block
        let mut output = std::array::from_fn(|_| Ciphertext::Trivial(false));
        let output_start = self.output_end - AES_128_OUTPUT_BITSIZE as u32;
        
        for i in output_start..self.output_end {
            let output_idx = (i - output_start) as usize;
            output[output_idx] = values.get(&i)
                .expect("Missing output wire value")
                .clone();
        }

        output
    }

    /// Generates multiple CTR mode blocks in parallel
    pub fn aes_ctr_blocks(
        &self,
        iv: [Ciphertext; AES_BLOCK_SIZE_BITS],
        count: usize,
    ) -> Vec<[Ciphertext; AES_128_OUTPUT_BITSIZE]> {
        match count {
            0 => vec![],
            1 => vec![self.execute(iv)],
            _ => self.generate_parallel_blocks(iv, count)
        }
    }

    /// Parallel block generation using work stealing
    fn generate_parallel_blocks(
        &self,
        iv: [Ciphertext; AES_BLOCK_SIZE_BITS],
        count: usize,
    ) -> Vec<[Ciphertext; AES_128_OUTPUT_BITSIZE]> {
        let (head, tail) = rayon::join(
            || self.execute(iv.clone()),
            || self.process_tail_blocks(&iv, count)
        );

        let mut results = Vec::with_capacity(count);
        results.push(head);
        results.extend(tail);
        results
    }

    /// Process remaining blocks in parallel
    fn process_tail_blocks(
        &self,
        iv: &[Ciphertext; AES_BLOCK_SIZE_BITS],
        count: usize,
    ) -> Vec<[Ciphertext; AES_128_OUTPUT_BITSIZE]> {
        self.get_blocks(iv, count - 1)
            .into_par_iter()
            .map(|block| self.execute(block))
            .collect()
    }

    /// Homomorphically generate incremented blocks for CTR mode
    fn get_blocks(
        &self,
        iv: &[Ciphertext; AES_BLOCK_SIZE_BITS],
        count: usize,
    ) -> Vec<[Ciphertext; AES_BLOCK_SIZE_BITS]> {
        let xor_cache: DashMap<(usize, bool), Ciphertext> = DashMap::with_capacity(128);
        let and_cache: DashMap<(usize, bool), Ciphertext> = DashMap::with_capacity(128);

        (1..=count).into_par_iter().map(|i| {
            let counter_bits = BitVec::from_bytes(&(i as u128).to_be_bytes());
            let mut carry = Ciphertext::Trivial(false);
            let mut block = iv.clone();

            for bit_pos in 0..AES_BLOCK_SIZE_BITS {
                let bit = counter_bits.get(AES_BLOCK_SIZE_BITS - bit_pos - 1)
                    .unwrap_or(false);

                // Get cached operations or compute new
                let (a_xor_b, a_and_b) = self.get_or_compute_operations(
                    &mut block,
                    bit_pos,
                    bit,
                    &xor_cache,
                    &and_cache
                );

                // Full adder logic
                let (sum, new_carry) = self.bit_full_adder(a_xor_b, a_and_b, carry);
                block[bit_pos] = sum;
                carry = new_carry;
            }

            block
        }).collect()
    }

    /// Helper method for cached operation computation
    #[inline]
    fn get_or_compute_operations(
        &self,
        block: &mut [Ciphertext; AES_BLOCK_SIZE_BITS],
        bit_pos: usize,
        bit: bool,
        xor_cache: &DashMap<(usize, bool), Ciphertext>,
        and_cache: &DashMap<(usize, bool), Ciphertext>,
    ) -> (Ciphertext, Ciphertext) {
        if let (Some(xor), Some(and)) = (xor_cache.get(&(bit_pos, bit)), and_cache.get(&(bit_pos, bit))) {
            (xor.clone(), and.clone())
        } else {
            let a = &block[bit_pos];
            let b = Ciphertext::Trivial(bit);
            
            let (xor, and) = rayon::join(
                || self.server_key.xor(a, &b),
                || self.server_key.and(a, &b)
            );
            
            xor_cache.insert((bit_pos, bit), xor.clone());
            and_cache.insert((bit_pos, bit), and.clone());
            
            (xor, and)
        }
    }

    /// Full adder implementation using precomputed XOR and AND results
    #[inline]
    fn bit_full_adder(
        &self,
        a_xor_b: Ciphertext,
        a_and_b: Ciphertext,
        cin: Ciphertext,
    ) -> (Ciphertext, Ciphertext) {
        rayon::join(
            || self.server_key.xor(&a_xor_b, &cin),
            || self.server_key.or(&a_and_b, &self.server_key.and(&cin, &a_xor_b))
        )
    }
}
