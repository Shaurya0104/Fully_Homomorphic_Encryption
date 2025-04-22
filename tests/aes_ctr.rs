use fhe_aes::{BoolFheAes, encrypt_reference_aes128};
use aes::{Aes128, cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray}};
use tfhe::boolean::prelude::*;
use test_case::test_case;

const TEST_ITERATIONS: usize = 5;

#[test_case(
    [0x00; 16],
    [0x00; 16],
    [
        0xfd, 0xe4, 0xfb, 0xae, 0x4a, 0x09, 0xe0, 0x20, 0xef, 0xf7, 0x22, 0x96, 0x9f, 0x83, 0x83, 0x2b,
    ]
)]
#[test_case(
    [
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    ],
    [
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    ],
    [
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    ]
)]
fn test_aes_ctr_mode(
    plaintext: [u8; 16],
    key: [u8; 16],
    expected_ciphertext: [u8; 16],
) {
    for _ in 0..TEST_ITERATIONS {
        let (client_key, server_key) = gen_keys();
        
        let fhe_aes = BoolFheAes::new(server_key);
        let fhe_key = BoolFheAes::encrypt_key(&client_key, &key);
        let fhe_iv = BoolFheAes::encrypt_iv(&client_key, &plaintext);
        
        fhe_aes.expand_key(fhe_key);
        let outputs = fhe_aes.aes_ctr_blocks(fhe_iv, 1);
        
        let decrypted = BoolFheAes::decrypt_output(&client_key, &outputs[0]);
        assert_eq!(decrypted, expected_ciphertext);
    }
}

#[test]
fn test_multiple_blocks() {
    let (client_key, server_key) = gen_keys();
    let key = [0u8; 16];
    let iv = [1u8; 16];
    
    let fhe_aes = BoolFheAes::new(server_key);
    let fhe_key = BoolFheAes::encrypt_key(&client_key, &key);
    let fhe_iv = BoolFheAes::encrypt_iv(&client_key, &iv);
    
    fhe_aes.expand_key(fhe_key);
    let outputs = fhe_aes.aes_ctr_blocks(fhe_iv, 3);
    
    assert_eq!(outputs.len(), 3);
    outputs.iter().for_each(|output| {
        let decrypted = BoolFheAes::decrypt_output(&client_key, output);
        assert_ne!(decrypted, [0u8; 16]);
    });
}
