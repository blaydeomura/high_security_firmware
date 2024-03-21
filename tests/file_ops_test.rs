// Import the necessary modules and types
use rust_cli::wallet::Wallet;
use rust_cli::file_ops::{sign, verify};
use rust_cli::persona::Persona;
use std::path::Path;
use criterion::{Criterion};
use criterion::{criterion_group, criterion_main};


/* 
   Unit test verifies the correctness of the sign and verify operations. 
   It creates a new wallet, adds a test persona to it, signs a file using the persona, 
   and then verifies the signature. If any of these steps fail, the test will fail.
*/ 
#[test]
fn test_file_operations() {

    // Create a new Wallet instance
    let mut wallet = Wallet::new();

    // Create a test persona for signing
    let test_persona = Persona::new("test_persona".to_string(), 1); // Change the cs_id as needed

    // Add the test persona to the wallet
    wallet.save_persona(test_persona.clone()).expect("Failed to save persona to wallet");

    // Path to the file to sign
    let file_path = "files/file_test_2.txt";

    // Sign the file using the persona from the wallet
    sign(&test_persona.get_name(), file_path, &wallet).expect("Failed to generate signature");

    // Path to the signature file
    let signature_file_path = format!("signatures/{}_{}.sig", test_persona.get_name(), Path::new(file_path).file_name().unwrap().to_str().unwrap());

    // Verify the signature
    verify(&test_persona.get_name(), file_path, &signature_file_path, &wallet).expect("Failed to verify signature");
}

/*
The criterion crate in Rust is specifically designed for benchmarking and measuring the performance of code. 
It provides a framework for writing benchmarks and running them with statistical analysis.

I am using criterion to create benchmarks, it runs the code multiple times and collects data on the execution time of each iteration. 
Then, it performs statistical analysis on the collected data to provide more accurate and meaningful measurements of performance, 
including metrics such as average execution time, standard deviation, and confidence intervals.

By using criterion benchmarks, you can make informed decisions about the performance characteristics of your code 
and identify potential optimizations or regressions.

To run the criterion benchmarks performance tests simply type
    "cargo bench" in the command line 
*/

/* 
Criterion benchmarks performance test to measure the efficiency of the sign and verify operations using the criterion crate. 
Each benchmark function is defined to measure the execution time of the corresponding operation (sign or verify).
These benchmarks are useful for evaluating the performance of the algorithms over multiple iterations and providing statistical analysis on execution times. 
*/

fn sign_benchmark(c: &mut Criterion) {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1); // Change the cs_id as needed
    wallet.save_persona(test_persona.clone()).expect("Failed to save persona to wallet");
    let file_path = "files/file_test_2.txt";

    c.bench_function("sign", |b| b.iter(|| sign(&test_persona.get_name(), file_path, &wallet)));
}

fn verify_benchmark(c: &mut Criterion) {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1); // Change the cs_id as needed
    wallet.save_persona(test_persona.clone()).expect("Failed to save persona to wallet");
    let file_path = "files/file_test_2.txt";
    let signature_file_path = format!("signatures/{}_{}.sig", test_persona.get_name(), Path::new(file_path).file_name().unwrap().to_str().unwrap());
    sign(&test_persona.get_name(), file_path, &wallet).expect("Failed to generate signature");

    c.bench_function("verify", |b| b.iter(|| verify(&test_persona.get_name(), file_path, &signature_file_path, &wallet)));
}

// Define benchmark group
criterion_group!(benches, sign_benchmark, verify_benchmark);

// Specify entry point for running the benchmarks
criterion_main!(benches);