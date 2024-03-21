// Import necessary modules and types
use rust_cli::wallet::Wallet;
use rust_cli::persona::Persona;
use criterion::{criterion_group, criterion_main, Criterion};

// Unit test verifies the correctness of the generate and remove operations. 
#[test]

/*
test_generate_persona:
   This test ensures that a persona can be generated and saved in the wallet correctly. 
   It creates a new wallet, generates a test persona, saves it, and then verifies if it exists in the wallet.
*/
fn test_generate_persona() {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);

    assert!(wallet.save_persona(test_persona.clone()).is_ok());
    assert_eq!(wallet.keys.len(), 1);

    // Check if the persona exists in the wallet
    assert!(match wallet.get_persona("test_persona") {
        Some(persona) => *persona == test_persona, // Dereference persona to compare with test_persona
        None => false,
    });
}

#[test]
/*
test_remove_persona: 
This test ensures that a persona can be removed from the wallet. 
It creates a new wallet, generates a test persona, saves it, removes it, and then verifies if it has been removed from the wallet.
*/
fn test_remove_persona() {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);

    wallet.save_persona(test_persona.clone()).unwrap();
    assert_eq!(wallet.keys.len(), 1);

    // Remove the persona from the wallet
    assert!(wallet.remove_persona("test_persona").is_ok());

    // Check if the persona has been removed from the wallet
    assert_eq!(wallet.get_persona("test_persona"), None);
}

// Define benchmark functions to measure the performance of the Wallet operations, enerate and remove 

/*
generate_benchmark: This benchmark measures the time taken to generate and save a persona in the wallet.
*/
fn generate_benchmark(c: &mut Criterion) {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);

    c.bench_function("generate_persona", |b| b.iter(|| wallet.save_persona(test_persona.clone())));
}

/*
remove_benchmark: This benchmark measures the time taken to remove a persona from the wallet.
*/
fn remove_benchmark(c: &mut Criterion) {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);
    wallet.save_persona(test_persona.clone()).unwrap();

    c.bench_function("remove_persona", |b| b.iter(|| wallet.remove_persona("test_persona")));
}

// Define the criterion group
criterion_group!(
    wallet_benches,
    generate_benchmark,
    remove_benchmark,
);

// Run the benchmarks
criterion_main!(wallet_benches);
