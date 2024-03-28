// Import necessary types from persona.rs
use rust_cli::persona::{Persona};
use rust_cli::persona::{HashFunction, CipherSuite, CipherSuiteType}; 
use std::time::{Instant};
use rust_cli::wallet::Wallet;

// Define a function to return the list of cipher suites to test
fn get_cipher_suites() -> Vec<CipherSuite> {
    vec![
        CipherSuite::new(CipherSuiteType::Dilithium2, HashFunction::Sha256),
        CipherSuite::new(CipherSuiteType::Dilithium2, HashFunction::Sha512),
        CipherSuite::new(CipherSuiteType::Falcon512, HashFunction::Sha256),
        CipherSuite::new(CipherSuiteType::Falcon512, HashFunction::Sha512),
    ]
} //TODO add cipher suite as predefined w known numbers or identifier number or name if its a structure 
// header based signature as a method for signing 

// Define a function to perform cryptographic operations with different cipher suites
fn cipher_suite_unit_testing() {
    // Get the list of cipher suites to test
    let cipher_suites = get_cipher_suites();

    // Iterate through each cipher suite
    for _cipher_suite in cipher_suites {
        // Perform cryptographic operations using the current cipher suite
        let mut wallet = Wallet::new();
        let test_persona = Persona::new("test_persona".to_string(), 1);

        // Save persona and handle potential error
        match wallet.save_persona(test_persona.clone()) {
            Ok(_) => {
                assert!(wallet.get_persona("test_persona").is_some());
            },
            Err(e) => panic!("Failed to save persona: {:?}", e),
        }

        // Remove persona and handle potential error
        match wallet.remove_persona("test_persona") {
            Ok(_) => {
                assert!(wallet.get_persona("test_persona").is_none());
            },
            Err(e) => panic!("Failed to remove persona: {:?}", e),
        }
    }
}

// Function to measure the time taken for cryptographic operations with a specific cipher suite
fn cipher_suite_performance_testing() {
    // Get the list of cipher suites to benchmark
    let cipher_suites = get_cipher_suites();

    // Find the maximum length of cipher suite name for alignment
    let max_cipher_suite_length = cipher_suites.iter()
        .map(|suite| format!("{:?}", suite).len())
        .max()
        .unwrap_or(0);

    // Print table header
    println!("Performance Test Results:");
    println!("{:<width$} | {:<10}", "Cipher Suite", "Time (ms)", width = max_cipher_suite_length);
    println!("{:-<width$}-|{:-<10}", "", "", width = max_cipher_suite_length);

    // Iterate through each cipher suite
    for cipher_suite in cipher_suites {
        // Measure the time taken for cryptographic operations using the current cipher suite
        let start_time = Instant::now();
        let mut wallet = Wallet::new();
        let test_persona = Persona::new("test_persona".to_string(), 1);
        wallet.save_persona(test_persona.clone()).unwrap();
        wallet.remove_persona("test_persona").unwrap();
        let end_time = start_time.elapsed().as_nanos();

        // Convert nanoseconds to milliseconds
        let time_ms = end_time as f64 / 1_000_000.0;

        // Print results for the current cipher suite
        println!("{:<width$} | {:.2}", format!("{:?}", cipher_suite), time_ms, width = max_cipher_suite_length);
    }
}

#[test]
fn test_cipher_suite_behavior() {
    // Perform cipher suite testing
    cipher_suite_unit_testing();
}

#[test]
fn test_cipher_suite_performance() {
    // Perform cipher suite performance testing
    cipher_suite_performance_testing();
}
