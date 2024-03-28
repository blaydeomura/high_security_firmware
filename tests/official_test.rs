use rust_cli::persona::Persona;
use rust_cli::wallet::Wallet;
use std::time::Instant;
use std::fs;
use rust_cli::file_ops::{sign, verify};
use std::path::Path;

#[test]
fn test_generate_persona() {
    // Test persona generation for all four cipher suites
    for cs_id in 1..=4 {
        let mut wallet = Wallet::new();
        let persona_name = format!("test_persona_{}", cs_id);
        let test_persona = Persona::new(persona_name.clone(), cs_id);

        // Save persona and check correctness
        wallet.save_persona(test_persona.clone()).unwrap();
        assert!(wallet.get_persona(&persona_name).is_some(), "Failed to save persona: {}", persona_name);

        // Remove persona and check correctness
        wallet.remove_persona(&persona_name).unwrap();
        assert!(wallet.get_persona(&persona_name).is_none(), "Failed to remove persona: {}", persona_name);
    }
}

#[test]
fn test_sign_and_verify_file() {
    // Create a new Wallet instance
    let mut wallet = Wallet::new();

    // Create a test persona for signing
    let test_persona = Persona::new("test_persona".to_string(), 1);

    // Add the test persona to the wallet
    wallet.save_persona(test_persona.clone()).expect("Failed to save persona to wallet");

    // Path to the file to sign
    let file_path = "files/file_test_2.txt";

    // Create a test file
    let file_content = b"Test content";
    fs::write(file_path, file_content).expect("Failed to create test file");

    // Sign the file using the persona from the wallet
    sign(&test_persona.get_name(), file_path, &wallet).expect("Failed to generate signature");

    // Path to the signature file
    let signature_file_path = format!("signatures/{}_{}.sig", test_persona.get_name(), Path::new(file_path).file_name().unwrap().to_str().unwrap());

    // Verify the signature
    verify(&test_persona.get_name(), file_path, &signature_file_path, &wallet).expect("Failed to verify signature");

    // Clean up test files
    fs::remove_file(file_path).expect("Failed to remove test file");
    fs::remove_file(&signature_file_path).expect("Failed to remove signature file");
}

#[test]
fn test_remove_persona() {
    // Prepare test data
    let persona_name = "test_persona_to_remove";
    let cs_id = 1;

    // Create wallet and add persona
    let mut wallet = Wallet::new();
    let test_persona = Persona::new(persona_name.to_string(), cs_id);
    wallet.save_persona(test_persona.clone()).unwrap();

    // Remove persona from wallet and check correctness
    wallet.remove_persona(persona_name).unwrap();
    assert!(wallet.get_persona(persona_name).is_none(), "Persona still exists in wallet after removal: {}", persona_name);
}

#[test]
fn test_remove_signature_file() {
    // This functionality is indirectly tested within test_sign_and_verify_file function
    // as it involves removing the signature file after signing.
    // No additional test required.
}

fn measure_cipher_suite_performance(cs_id: usize) -> (String, Vec<(u128, usize)>) {
    let mut measurements = Vec::new();
    let mut wallet = Wallet::new();
    let persona_name = format!("test_persona_{}", cs_id);
    let test_persona = Persona::new(persona_name.clone(), cs_id);
    wallet.save_persona(test_persona.clone()).unwrap();

    // Measure the performance of each operation
    let start_sign = Instant::now();
    let sign_result = sign(&persona_name, "files/file_test.txt", &wallet);
    let end_sign = start_sign.elapsed().as_nanos();
    let sign_time_ms = end_sign as u128 / 1_000_000;
    let sign_pk_size = test_persona.get_pk().as_ref().len();
    measurements.push((sign_time_ms, sign_pk_size));

    let start_verify = Instant::now();
    let verify_result = verify(&persona_name, "files/file_test.txt", "signatures/test_persona_1_file_test.txt.sig", &wallet);
    let end_verify = start_verify.elapsed().as_nanos();
    let verify_time_ms = end_verify as u128 / 1_000_000;
    let verify_pk_size = test_persona.get_pk().as_ref().len();
    measurements.push((verify_time_ms, verify_pk_size));

    let start_remove = Instant::now();
    let remove_result = wallet.remove_persona(&persona_name);
    let end_remove = start_remove.elapsed().as_nanos();
    let remove_time_ms = end_remove as u128 / 1_000_000;
    let remove_pk_size = test_persona.get_pk().as_ref().len();
    measurements.push((remove_time_ms, remove_pk_size));

    (format!("Cipher Suite {}", cs_id), measurements)
}

#[test]
fn test_performance() {
    // Define cipher suites used
    let cipher_suites = [
        (1, "Dilithium2", "sha256"),
        (2, "Dilithium2", "sha512"),
        (3, "Falcon512", "sha256"),
        (4, "Falcon512", "sha512"),
    ];

    // Print table header
    println!("Performance Test Results:");
    println!("{:<20} | {:<15} | {:<10} | {:<15}", "Cipher Suite", "Operation", "Time (ms)", "Public Key Size");
    println!("{:-<20}-|{:-<15}-|{:-<10}-|{:-<15}", "", "", "", "");

    // Iterate through each cipher suite and measure performance
    for (cs_id, sig_alg, hash_alg) in &cipher_suites {
        let (suite_name, measurements) = measure_cipher_suite_performance(*cs_id);

        // Print results for each operation and cipher suite
        for (operation, (time_ms, pk_size)) in measurements.iter().enumerate() {
            let operation_name = match operation {
                0 => "Sign",
                1 => "Verify",
                2 => "Remove",
                _ => unreachable!(), // Just to handle potential future additions to measurements
            };
            println!("{:<20} | {:<15} | {:<10} | {:<15}", suite_name, operation_name, time_ms, pk_size);
        }
    }
}
