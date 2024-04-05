use rust_cli::persona::Persona;
use rust_cli::wallet::Wallet;
use std::fs;
use rust_cli::file_ops::{sign, verify};
use std::time::Instant;
use tempfile::tempdir;


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
    let mut wallet = Wallet::new();
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("file_test.txt");
    fs::write(&file_path, "Test file content").unwrap();

    // Test signing and verifying for each cipher suite
    for cs_id in 1..=4 {
        let name = format!("TestPersona{}", cs_id);
        let start_time = Instant::now();

        // Ensure persona exists
        wallet.save_persona(Persona::new(name.clone(), cs_id)).unwrap();

        // Sign file
        let output_path = dir.path().join(format!("signed_file_cs_id{}.txt", cs_id));
        sign(&name, file_path.to_str().unwrap(), output_path.to_str().unwrap(), &wallet).unwrap();

        // Verify signature
        verify(&name, output_path.to_str().unwrap(), file_path.to_str().unwrap(), &wallet).unwrap();

        let end_time = Instant::now();
        println!("Time taken to sign and verify file with cs_id {}: {:?}", cs_id, end_time - start_time);

        // Clean up
        fs::remove_file(output_path.clone()).unwrap();
    }
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
    let _sign_result = sign(&persona_name, "files/file_test.txt", "output_signature_file_path", &wallet);
    let end_sign = start_sign.elapsed().as_nanos();
    let sign_time_ms = end_sign as u128 / 1_000_000;
    let sign_pk_size = test_persona.get_pk().as_ref().len();
    measurements.push((sign_time_ms, sign_pk_size));

    let start_verify = Instant::now();
    let _verify_result = verify(&persona_name, "files/file_test.txt", "signatures/test_persona_1_file_test.txt.sig", &wallet);
    let end_verify = start_verify.elapsed().as_nanos();
    let verify_time_ms = end_verify as u128 / 1_000_000;
    let verify_pk_size = test_persona.get_pk().as_ref().len();
    measurements.push((verify_time_ms, verify_pk_size));

    let start_remove = Instant::now();
    let _remove_result = wallet.remove_persona(&persona_name);
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
    for (cs_id, _sig_alg, _hash_alg) in &cipher_suites {
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
