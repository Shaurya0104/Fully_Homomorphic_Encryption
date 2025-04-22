//! Main module for FHE-AES implementation

mod key;
mod blocks;

use crate::circuit::Gate;
use dashmap::DashMap;
use rayon::prelude::*;
use std::collections::HashSet;
use tfhe::boolean::prelude::*;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit, consts::U16};
use aes::Aes128;
use crate::utils::constants::*;



pub use blocks::*;
pub use key::*;

/// Main FHE-AES structure
pub struct BoolFheAes {
    pub(crate) instructions: Vec<Gate>,
    pub(crate) output_end: u32,
    pub(crate) server_key: ServerKey,
    pub(crate) key_expand_reachable: HashSet<u32>,
    pub(crate) expanded_key_outputs: DashMap<u32, Ciphertext>,
}


pub fn encrypt_reference_aes128(
    blocks: Vec<[u8; AES_BLOCK_SIZE]>,
    key: [u8; AES_128_KEY_SIZE],
) -> Vec<GenericArray<u8, U16>> {
    let aes = Aes128::new(&GenericArray::from(key));
    blocks
        .iter()
        .map(|iv| {
            let mut block = GenericArray::clone_from_slice(iv);
            aes.encrypt_block(&mut block);
            block
        })
        .collect::<Vec<_>>()
}


impl BoolFheAes {
    /// Creates a new BoolFheAes instance with loaded circuit
    pub fn new(server_key: ServerKey) -> Self {
        let mut circuit = include_str!("./aes_128_extended.txt").lines();
        let header = circuit.next().expect("Invalid circuit format");
        let (gate_count, output_end) = parse_header(header);
        
        let mut key_expand_reachable = HashSet::new();
        key_expand_reachable.extend(0..128);  // First 128 bits are key inputs

        let mut instructions = Vec::with_capacity(gate_count);
        
        // Skip input/output declarations
        circuit.next();
        circuit.next();

        for line in circuit.filter(|l| !l.trim().is_empty()) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let gate = parse_line(&parts, &key_expand_reachable);
            update_reachability(&gate, &mut key_expand_reachable);
            instructions.push(gate);
        }

        Self {
            instructions,
            output_end,
            server_key,
            key_expand_reachable,
            expanded_key_outputs: DashMap::new(),
        }
    }

    // Helper methods from original implementation
    #[inline]
    fn was_computed(&self, output: &u32, values: &DashMap<u32, Ciphertext>) -> bool {
        values.contains_key(output) || self.expanded_key_outputs.contains_key(output)
    }

    #[inline]
    fn expand_key_check(
        &self,
        output: &u32,
        values: &DashMap<u32, Ciphertext>,
        expand_key: bool,
    ) -> bool {
        self.was_computed(output, values)
            || (expand_key && !self.key_expand_reachable.contains(output))
    }

    #[inline]
    fn get_output(&self, output: &u32, values: &DashMap<u32, Ciphertext>) -> Ciphertext {
        values
            .get(output)
            .unwrap_or_else(|| {
                self.expanded_key_outputs
                    .get(output)
                    .expect("Output not found")
            })
            .clone()
    }

    #[inline]
    fn yield_or_compute(&self, values: &DashMap<u32, Ciphertext>, ilen: usize, i: usize) {
        if let Some(rayon::Yield::Idle) = rayon::yield_now() {
            (0..i).into_par_iter().for_each(|j| {
                self.execute_gate(&self.instructions[j], values);
            });
            (i + 1..ilen).into_par_iter().for_each(|j| {
                self.execute_gate(&self.instructions[j], values);
            });
        }
    }

    #[inline]
    fn wait_for_inputs(
        &self,
        values: &DashMap<u32, Ciphertext>,
        ilen: usize,
        i: usize,
        input1: &u32,
        input2: &u32,
    ) {
        while !self.was_computed(input1, values) || !self.was_computed(input2, values) {
            self.yield_or_compute(values, ilen, i);
        }
    }

    // Core execution methods remain here...
    // (execute_all, execute_gate, and helper methods from original code)
        /// Executes all the gates in the circuit in parallel:
    /// - if `expand_key` is `true`, it will only compute the gates that are reachable from the key input wires
    ///
    /// for each gate, it will wait until the inputs are computed and then compute the output.
    fn execute_all(&self, values: &DashMap<u32, Ciphertext>, expand_key: bool) {
        let ilen = self.instructions.len();
        (0..ilen).into_par_iter().for_each(|i| {
            let instr = &self.instructions[i];
            match instr {
                Gate::And {
                    input1,
                    input2,
                    output,
                } => {
                    if self.expand_key_check(output, values, expand_key) {
                        return;
                    }
                    self.wait_for_inputs(values, ilen, i, input1, input2);

                    let input1_ct = self.get_output(input1, values);
                    let input2_ct = self.get_output(input2, values);
                    if self.expand_key_check(output, values, expand_key) {
                        return;
                    }
                    let output_ct = self.server_key.and(&input1_ct, &input2_ct);
                    values.insert(*output, output_ct);
                }
                Gate::Inv { input, output } => {
                    if self.expand_key_check(output, values, expand_key) {
                        return;
                    }
                    while !self.was_computed(input, values) {
                        self.yield_or_compute(values, ilen, i);
                    }
                    let input_ct = self.get_output(input, values);
                    if self.expand_key_check(output, values, expand_key) {
                        return;
                    }
                    let output_ct = self.server_key.not(&input_ct);
                    values.insert(*output, output_ct);
                }
                Gate::Xor {
                    input1,
                    input2,
                    output,
                } => {
                    if self.expand_key_check(output, values, expand_key) {
                        return;
                    }
                    self.wait_for_inputs(values, ilen, i, input1, input2);

                    let input1_ct = self.get_output(input1, values);
                    let input2_ct = self.get_output(input2, values);
                    if self.expand_key_check(output, values, expand_key) {
                        return;
                    }
                    let output_ct = self.server_key.xor(&input1_ct, &input2_ct);
                    values.insert(*output, output_ct);
                }
                Gate::Mand { gates } => {
                    gates.par_iter().for_each(|(input1, input2, output)| {
                        if self.expand_key_check(output, values, expand_key) {
                            return;
                        }
                        self.wait_for_inputs(values, ilen, i, input1, input2);

                        let input1_ct = self.get_output(input1, values);
                        let input2_ct = self.get_output(input2, values);
                        if self.expand_key_check(output, values, expand_key) {
                            return;
                        }
                        let output_ct = self.server_key.and(&input1_ct, &input2_ct);
                        values.insert(*output, output_ct);
                    });
                }
            }
        });
    }

    /// Executes a single gate in the circuit:
    /// - if the output wire was already computed, it will return immediately
    /// - if the inputs are not computed, it will return immediately
    /// - otherwise, it will compute the output and store it in the values map.
    fn execute_gate(&self, instr: &Gate, values: &DashMap<u32, Ciphertext>) {
        match instr {
            Gate::And {
                input1,
                input2,
                output,
            } => {
                if self.was_computed(output, values)
                    || !self.was_computed(input1, values)
                    || !self.was_computed(input2, values)
                {
                    return;
                }

                let input1_ct = self.get_output(input1, values);
                let input2_ct = self.get_output(input2, values);
                if values.contains_key(output) {
                    return;
                }
                let output_ct = self.server_key.and(&input1_ct, &input2_ct);
                values.insert(*output, output_ct);
            }
            Gate::Inv { input, output } => {
                if self.was_computed(output, values) || !self.was_computed(input, values) {
                    return;
                }

                let input_ct = self.get_output(input, values);
                if self.was_computed(output, values) {
                    return;
                }
                let output_ct = self.server_key.not(&input_ct);
                values.insert(*output, output_ct);
            }
            Gate::Xor {
                input1,
                input2,
                output,
            } => {
                if self.was_computed(output, values)
                    || !self.was_computed(input1, values)
                    || !self.was_computed(input2, values)
                {
                    return;
                }

                let input1_ct = self.get_output(input1, values);
                let input2_ct = self.get_output(input2, values);
                if self.was_computed(output, values) {
                    return;
                }
                let output_ct = self.server_key.xor(&input1_ct, &input2_ct);
                values.insert(*output, output_ct);
            }
            Gate::Mand { gates } => {
                gates.par_iter().for_each(|(input1, input2, output)| {
                    if self.was_computed(output, values)
                        || !self.was_computed(input1, values)
                        || !self.was_computed(input2, values)
                    {
                        return;
                    }

                    let input1_ct = self.get_output(input1, values);
                    let input2_ct = self.get_output(input2, values);
                    if self.was_computed(output, values) {
                        return;
                    }
                    let output_ct = self.server_key.and(&input1_ct, &input2_ct);
                    values.insert(*output, output_ct);
                });
            }
        }
    }

}

fn parse_header(header: &str) -> (usize, u32) {
    let parts: Vec<&str> = header.split_whitespace().collect();
    (
        parts[0].parse().unwrap_or(36663),
        parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(36919)
    )
}

fn parse_line(parts: &[&str], reachable: &HashSet<u32>) -> Gate {
    match parts.last().unwrap() {
        &"AND" => Gate::And {
            input1: parts[2].parse().unwrap(),
            input2: parts[3].parse().unwrap(),
            output: parts[4].parse().unwrap(),
        },
        &"INV" => Gate::Inv {
            input: parts[2].parse().unwrap(),
            output: parts[3].parse().unwrap(),
        },
        &"XOR" => Gate::Xor {
            input1: parts[2].parse().unwrap(),
            input2: parts[3].parse().unwrap(),
            output: parts[4].parse().unwrap(),
        },
        &"MAND" => parse_mand(parts),
        _ => panic!("Unknown gate type"),
    }
}

fn parse_mand(parts: &[&str]) -> Gate {
    let count: usize = parts[1].parse().unwrap();
    let mut gates = Vec::with_capacity(count);
    
    for i in 0..count {
        let input1 = parts[2 + i].parse().unwrap();
        let input2 = parts[2 + count + i].parse().unwrap();
        let output = parts[2 + 2 * count + i].parse().unwrap();
        gates.push((input1, input2, output));
    }
    
    Gate::Mand { gates }
}

fn update_reachability(gate: &Gate, reachable: &mut HashSet<u32>) {
    match gate {
        Gate::And { input1, input2, output } |
        Gate::Xor { input1, input2, output } => {
            if reachable.contains(input1) && reachable.contains(input2) {
                reachable.insert(*output);
            }
        }
        Gate::Inv { input, output } => {
            if reachable.contains(input) {
                reachable.insert(*output);
            }
        }
        Gate::Mand { gates } => {
            for (in1, in2, out) in gates {
                if reachable.contains(in1) && reachable.contains(in2) {
                    reachable.insert(*out);
                }
            }
        }
    }
}
