// Import necessary modules and types
use rust_cli::file_ops::{sign, verify};
use rust_cli::persona::Persona;
use rust_cli::wallet::Wallet;
use std::fs;
use std::path::Path;

// Unit test to verify the correctness of the sign and verify operations
#[test]
fn test_file_operations() {
    // Create a new Wallet instance
    let mut wallet = Wallet::new();

    // Create a test persona for signing
    let test_persona = Persona::new("test_persona".to_string(), 1);

    // Add the test persona to the wallet
    wallet
        .save_persona(test_persona.clone())
        .expect("Failed to save persona to wallet");

    // Path to the file to sign
    let file_path = "files/file_test_2.txt";

    // Sign the file using the persona from the wallet
    sign(&test_persona.get_name(), file_path, &wallet).expect("Failed to generate signature");

    // Path to the signature file
    let signature_file_path = format!(
        "signatures/{}_{}.sig",
        test_persona.get_name(),
        Path::new(file_path).file_name().unwrap().to_str().unwrap()
    );

    // Verify the signature
    verify(
        &test_persona.get_name(),
        file_path,
        &signature_file_path,
        &wallet,
    )
    .expect("Failed to verify signature");
}

// Function to measure the time taken for signing a file
fn sign_benchmark() -> (usize, u128) {
    let start_time = Instant::now();

    // Create a new Wallet instance
    let mut wallet = Wallet::new();

    // Create a test persona for signing
    let test_persona = Persona::new("test_persona".to_string(), 1);

    // Add the test persona to the wallet
    wallet
        .save_persona(test_persona.clone())
        .expect("Failed to save persona to wallet");

    // Path to the file to sign
    let file_path = "files/file_test_2.txt";

    // Sign the file using the persona from the wallet
    sign(&test_persona.get_name(), file_path, &wallet).expect("Failed to generate signature");

    // Calculate the elapsed time for signing
    let end_time = start_time.elapsed().as_millis();

    // Return the size of the public key and the elapsed time for signing
    (test_persona.get_pk().as_ref().len(), end_time)
}

// Function to measure the time taken for verifying a signature
fn verify_benchmark() -> u128 {
    let start_time = Instant::now();

    // Create a new Wallet instance
    let mut wallet = Wallet::new();

    // Create a test persona for signing
    let test_persona = Persona::new("test_persona".to_string(), 1);

    // Add the test persona to the wallet
    wallet
        .save_persona(test_persona.clone())
        .expect("Failed to save persona to wallet");

    // Path to the file to sign
    let file_path = "files/file_test_2.txt";

    // Sign the file using the persona from the wallet
    sign(&test_persona.get_name(), file_path, &wallet).expect("Failed to generate signature");

    // Path to the signature file
    let signature_file_path = format!(
        "signatures/{}_{}.sig",
        test_persona.get_name(),
        Path::new(file_path).file_name().unwrap().to_str().unwrap()
    );

    // Verify the signature
    verify(
        &test_persona.get_name(),
        file_path,
        &signature_file_path,
        &wallet,
    )
    .expect("Failed to verify signature");

    // Calculate the elapsed time for verifying
    let end_time = start_time.elapsed().as_millis();
    end_time
}

// Unit test to measure performance
#[test]
fn test_performance() {
    // Measure signing time and get the size of the public key
    let (pk_size, sign_time) = sign_benchmark();
    // Measure verification time
    let verify_time = verify_benchmark();

    // Convert time from nanoseconds to milliseconds
    let sign_time_ms = sign_time as f64;
    let verify_time_ms = verify_time as f64;

    // Print the results in a table format
    println!("Operation\tSize of Public Key\tTime (ms)");
    println!("---------------------------------------------------");
    println!("Sign\t\t{}\t\t\t{:.2}", pk_size, sign_time_ms);
    println!("Verify\t\t\t\t\t{:.2}", verify_time_ms);
}
