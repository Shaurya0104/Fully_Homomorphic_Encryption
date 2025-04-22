//! Circuit representation and parsing for AES-128 FHE implementation

use crate::utils::constants::{AES_128_KEY_SIZE_BITS, AES_BLOCK_SIZE_BITS};
use bit_vec::BitVec;
use std::collections::HashSet;

mod parser;

pub use parser::CircuitParser;

/// Represents a single gate in the boolean circuit
#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    And {
        input1: u32,
        input2: u32,
        output: u32,
    },
    Inv {
        input: u32,
        output: u32,
    },
    Xor {
        input1: u32,
        input2: u32,
        output: u32,
    },
    Mand {
        gates: Vec<(u32, u32, u32)>,
    },
}

/// Contains the parsed circuit structure
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub key_expand_reachable: HashSet<u32>,
    pub output_end: u32,
}

impl Circuit {
    /// Creates a new circuit from the embedded AES-128 circuit definition
    pub fn aes_128() -> Self {
        let circuit_text = include_str!("./aes_128_extended.txt");
        CircuitParser::parse(circuit_text)
    }
}
