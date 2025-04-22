use criterion::{criterion_group, criterion_main, Criterion};
use fhe_aes::BoolFheAes;
use tfhe::boolean::prelude::*;

fn bench_key_expansion(c: &mut Criterion) {
    let (client_key, server_key) = gen_keys();
    let key = [0u8; 16];
    let fhe_key = BoolFheAes::encrypt_key(&client_key, &key);

    c.bench_function("key_expansion", |b| {
        b.iter(|| {
            let fhe_aes = BoolFheAes::new(server_key.clone());
            fhe_aes.expand_key(fhe_key.clone());
        })
    });
}

fn bench_block_encryption(c: &mut Criterion) {
    let (client_key, server_key) = gen_keys();
    let fhe_aes = BoolFheAes::new(server_key);
    let key = [0u8; 16];
    let iv = [1u8; 16];
    
    let fhe_key = BoolFheAes::encrypt_key(&client_key, &key);
    let fhe_iv = BoolFheAes::encrypt_iv(&client_key, &iv);
    
    fhe_aes.expand_key(fhe_key);

    let mut group = c.benchmark_group("AES-CTR");
    for blocks in [1, 2, 4].iter() {
        group.bench_with_input(
            format!("{}_blocks", blocks),
            blocks,
            |b, &num| b.iter(|| fhe_aes.aes_ctr_blocks(fhe_iv.clone(), num))
        );
    }
    group.finish();
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_key_expansion, bench_block_encryption
}
criterion_main!(benches);
