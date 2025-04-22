//! MAND (Multiple AND) gate implementation

use super::*;
use dashmap::DashMap;
use rayon::prelude::*;
use tfhe::boolean::prelude::*;
use std::collections::HashSet;

/// Parses MAND gate from circuit line parts
pub fn parse_mand(parts: &[&str]) -> Gate {
    let gate_count: usize = parts[1].parse().expect("Invalid MAND format");
    let mut gates = Vec::with_capacity(gate_count);
    
    for i in 0..gate_count {
        let input1 = parts[2 + i].parse().unwrap();
        let input2 = parts[2 + gate_count + i].parse().unwrap();
        let output = parts[2 + 2*gate_count + i].parse().unwrap();
        gates.push((input1, input2, output));
    }
    
    Gate::Mand { gates }
}

/// Executes a batch of AND operations in parallel
pub fn execute_mand(
    gates: &[(u32, u32, u32)],
    server_key: &ServerKey,
    values: &DashMap<u32, Ciphertext>,
    expand_key: bool,
    key_reachable: &HashSet<u32>,
) {
    gates.par_iter().for_each(|(in1, in2, out)| {
        execute_and(*in1, *in2, *out, server_key, values, expand_key, key_reachable);
    });
}

/// Single AND gate execution logic
pub fn execute_and(
    input1: u32,
    input2: u32,
    output: u32,
    server_key: &ServerKey,
    values: &DashMap<u32, Ciphertext>,
    expand_key: bool,
    key_reachable: &HashSet<u32>,
) {
    if !should_compute(output, values, expand_key, key_reachable) {
        return;
    }

    let a = get_value(input1, values);
    let b = get_value(input2, values);
    
    let result = server_key.and(&a, &b);
    values.insert(output, result);
}

/// Inverter execution logic
pub fn execute_inv(
    input: u32,
    output: u32,
    server_key: &ServerKey,
    values: &DashMap<u32, Ciphertext>,
    expand_key: bool,
    key_reachable: &HashSet<u32>,
) {
    if !should_compute(output, values, expand_key, key_reachable) {
        return;
    }

    let a = get_value(input, values);
    let result = server_key.not(&a);
    values.insert(output, result);
}

/// XOR gate execution logic
pub fn execute_xor(
    input1: u32,
    input2: u32,
    output: u32,
    server_key: &ServerKey,
    values: &DashMap<u32, Ciphertext>,
    expand_key: bool,
    key_reachable: &HashSet<u32>,
) {
    if !should_compute(output, values, expand_key, key_reachable) {
        return;
    }

    let a = get_value(input1, values);
    let b = get_value(input2, values);
    let result = server_key.xor(&a, &b);
    values.insert(output, result);
}

/// Helper to check if output should be computed
fn should_compute(
    output: u32,
    values: &DashMap<u32, Ciphertext>,
    expand_key: bool,
    key_reachable: &HashSet<u32>,
) -> bool {
    !values.contains_key(&output) && 
    !(expand_key && !key_reachable.contains(&output))
}

/// Helper to get value from storage with fallback
fn get_value(
    input: u32,
    values: &DashMap<u32, Ciphertext>,
) -> Ciphertext {
    values.get(&input)
        .expect("Missing input value")
        .clone()
}
