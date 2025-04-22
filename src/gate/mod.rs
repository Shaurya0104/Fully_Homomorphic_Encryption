//! Gate types and operations for the boolean circuit

mod mand;

use rayon::prelude::*;
use dashmap::DashMap;
use tfhe::boolean::prelude::*;
use std::collections::HashSet;

/// Represents a single gate in the boolean circuit
#[derive(Debug, PartialEq, Eq)]
pub enum Gate {
    /// AND gate with two inputs and one output
    And {
        input1: u32,
        input2: u32,
        output: u32,
    },
    /// Inverter (NOT gate) with one input and one output
    Inv {
        input: u32,
        output: u32,
    },
    /// XOR gate with two inputs and one output
    Xor {
        input1: u32,
        input2: u32,
        output: u32,
    },
    /// Multiple AND gates executed in parallel
    Mand {
        gates: Vec<(u32, u32, u32)>,
    },
}

/// Common interface for gate operations
pub trait GateExecutor {
    fn execute(
        &self,
        server_key: &ServerKey,
        values: &DashMap<u32, Ciphertext>,
        expand_key: bool,
        key_reachable: &HashSet<u32>,
    );
}

impl GateExecutor for Gate {
    fn execute(
        &self,
        server_key: &ServerKey,
        values: &DashMap<u32, Ciphertext>,
        expand_key: bool,
        key_reachable: &HashSet<u32>,
    ) {
        match self {
            Gate::And { input1, input2, output } => 
                mand::execute_and(*input1, *input2, *output, server_key, values, expand_key, key_reachable),
            Gate::Inv { input, output } => 
                mand::execute_inv(*input, *output, server_key, values, expand_key, key_reachable),
            Gate::Xor { input1, input2, output } => 
                mand::execute_xor(*input1, *input2, *output, server_key, values, expand_key, key_reachable),
            Gate::Mand { gates } => 
                mand::execute_mand(gates, server_key, values, expand_key, key_reachable),
        }
    }
}

pub use mand::parse_mand;
