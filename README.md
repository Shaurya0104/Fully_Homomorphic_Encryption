# FHE-AES: Fully Homomorphic AES-128 Implementation

![Rust](https://img.shields.io/badge/Rust-1.72+-blue)
![TFHE](https://img.shields.io/badge/TFHE-0.4.1-green)

A Rust implementation of AES-128 block cipher using Fully Homomorphic Encryption (FHE) with the [TFHE](https://github.com/zama-ai/tfhe-rs) library, based on boolean circuits.

## Features

- 🔒 AES-128 encryption in fully homomorphic domain
- ⚡ Parallel execution using Rayon
- 📟 Command-line interface for operations
- 🔄 CTR mode implementation
- 🔍 Integrated reference AES implementation
- ⏱️ Performance benchmarking

## Installation

Requires Rust 1.72+ and TFHE dependencies
cargo build --release --features=boolean,integer,x86_64-unix



## Usage

### CLI Interface

RUST_MIN_STACK=33554432 cargo run --release --bin fhe-aes -- encrypt
-k 000102030405060708090a0b0c0d0e0f
-i 00112233445566778899aabbccddeeff
-n 2



**Parameters**:
- `-k/--key`: 128-bit AES key (hex)
- `-i/--iv`: 128-bit IV (hex)
- `-n/--count`: Number of blocks
- `-s/--slow`: Use integer FHE implementation

## Project Structure
```
fhe-aes/
├── Cargo.toml
├── src/
│ ├── lib.rs # Core library exports
│ ├── circuit/ # Boolean circuit processing
│ ├── gate/ # Logic gate implementations
│ ├── fhe_aes/ # FHE operations
│ ├── cli/ # Command-line interface
│ └── utils/ # Constants and helpers
├── tests/ # Integration tests
└── benches/ # Performance benchmarks
```


## Dependencies

- `tfhe`: FHE operations
- `aes`: Reference implementation
- `rayon`: Parallel processing
- `clap`: CLI parsing
- `dashmap`: Concurrent storage
- `bit-vec`: Bitwise operations

## Circuit Source

The AES circuit is based on the [SCALE-MAMBA](https://homes.esat.kuleuven.be/~nsmart/SCALE/) implementation from COSIC KU Leuven.

## Contributing

Contributions welcome! Please follow:
1. Fork repository
2. Create feature branch
3. Submit PR with tests

## License

Apache 2.0 - See [LICENSE](LICENSE) for details

## References

- [TFHE Documentation](https://docs.zama.ai/tfhe-rs)
- [AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
