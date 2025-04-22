//! Circuit file parser implementation

use super::{Circuit, Gate};
use std::collections::HashSet;
use crate::utils::constants::AES_128_KEY_SIZE_BITS;

pub struct CircuitParser;

impl CircuitParser {
    /// Parses the circuit text into a structured Circuit object
    pub fn parse(circuit: &str) -> Circuit {
        let mut lines = circuit.lines();
        let (gate_count, output_end) = parse_header(lines.next().expect("Missing circuit header"));

        let mut key_expand_reachable = HashSet::new();
        key_expand_reachable.extend(0..AES_128_KEY_SIZE_BITS as u32);

        let mut gates = Vec::with_capacity(gate_count);

        // Skip input/output declarations
        lines.next(); // INPUTS
        lines.next(); // OUTPUTS

        for line in lines.filter(|l| !l.trim().is_empty()) {
            let gate = parse_line(line, &key_expand_reachable);
            update_reachability(&gate, &mut key_expand_reachable);
            gates.push(gate);
        }

        Circuit {
            gates,
            key_expand_reachable,
            output_end,
        }
    }
}

fn parse_header(header: &str) -> (usize, u32) {
    let mut parts = header.split_whitespace();
    (
        parts.next().unwrap().parse().unwrap_or(36663),
        parts.next().unwrap().parse().unwrap_or(36919),
    )
}

fn parse_line(line: &str, reachable: &HashSet<u32>) -> Gate {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let op = parts.last().unwrap();
    
    match *op {
        "AND" => parse_and_gate(&parts),
        "INV" => parse_inv_gate(&parts),
        "XOR" => parse_xor_gate(&parts),
        "MAND" => parse_mand_gate(&parts),
        _ => panic!("Unknown gate operation: {}", op),
    }
}

fn parse_and_gate(parts: &[&str]) -> Gate {
    Gate::And {
        input1: parts[2].parse().unwrap(),
        input2: parts[3].parse().unwrap(),
        output: parts[4].parse().unwrap(),
    }
}

fn parse_inv_gate(parts: &[&str]) -> Gate {
    Gate::Inv {
        input: parts[2].parse().unwrap(),
        output: parts[3].parse().unwrap(),
    }
}

fn parse_xor_gate(parts: &[&str]) -> Gate {
    Gate::Xor {
        input1: parts[2].parse().unwrap(),
        input2: parts[3].parse().unwrap(),
        output: parts[4].parse().unwrap(),
    }
}

fn parse_mand_gate(parts: &[&str]) -> Gate {
    let gate_count: usize = parts[1].parse().unwrap();
    let mut gates = Vec::with_capacity(gate_count);

    for i in 0..gate_count {
        let input1 = parts[2 + i].parse().unwrap();
        let input2 = parts[2 + gate_count + i].parse().unwrap();
        let output = parts[2 + 2 * gate_count + i].parse().unwrap();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header() {
        let header = "36663 36919";
        assert_eq!(parse_header(header), (36663, 36919));
    }

    #[test]
    fn test_parse_mand_gate() {
        let line = "4 2 0 2 1 3 4 5 MAND";
        let gate = parse_line(line, &HashSet::new());
        
        if let Gate::Mand { gates } = gate {
            assert_eq!(gates, vec![(0, 2, 4), (1, 3, 5)]);
        } else {
            panic!("Expected MAND gate");
        }
    }
}
