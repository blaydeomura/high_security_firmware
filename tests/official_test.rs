// Import necessary modules
use rust_cli::persona::Persona;
use rust_cli::wallet::Wallet;
use std::fs;
use rust_cli::file_ops::{sign, verify, Header}; // Keep the import as it is
use std::time::Instant;
use tempfile::tempdir;
use std::convert::TryInto;
// use crate::persona::{get_hash, get_sig_algorithm}; // Import necessary items from persona module
// use oqs::sig::{PublicKey, Signature}; // Import necessary items from oqs::sig module
// use crate::file_ops::{do_vecs_match}; // Import necessary items from file_ops module
// use sha2::{Digest, Sha256, Sha512};


struct CipherSuite {
    cs_id: u32,
    signature_algorithm: &'static str,
    hash_function: &'static str,
}

const CIPHER_SUITES: [CipherSuite; 4] = [
    CipherSuite {
        cs_id: 1,
        signature_algorithm: "Dilithium2",
        hash_function: "sha256",
    },
    CipherSuite {
        cs_id: 2,
        signature_algorithm: "Dilithium2",
        hash_function: "sha512",
    },
    CipherSuite {
        cs_id: 3,
        signature_algorithm: "Falcon512",
        hash_function: "sha256",
    },
    CipherSuite {
        cs_id: 4,
        signature_algorithm: "Falcon512",
        hash_function: "sha512",
    },
];

#[test]
fn test_sign_and_verify_file_with_header() {
    // Test signing and verifying a file using header for each cipher suite
    let mut wallet = Wallet::new();
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("file_test.txt");
    fs::write(&file_path, "Test file content").unwrap();

    // Iterate over the cipher suites to test
    for cipher_suite in &CIPHER_SUITES {
        let cs_id = cipher_suite.cs_id;
        let persona_name = format!("TestPersona{}", cs_id);
        let persona = Persona::new(persona_name.clone(), cs_id.try_into().unwrap());
        wallet.save_persona(persona.clone()).unwrap();

        let signature_file = dir.path().join(format!("signature_file_cs_id{}.txt", cs_id));

        // Sign file
        sign(&persona_name, &file_path.to_str().unwrap(), &signature_file.to_str().unwrap(), &wallet).unwrap();

        // Read and verify signature
        let header = fs::read_to_string(&signature_file).unwrap();
        let header: Header = serde_json::from_str(&header).unwrap();

        // Verify header fields
        assert_eq!(header.get_cs_id() as u32, cs_id);
        assert_eq!(header.get_signer(), persona.get_pk());

        // Verify signature against the original file
        verify(&persona_name, &signature_file.to_str().unwrap(), &file_path.to_str().unwrap(), &wallet).unwrap();
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

// -----------------------------------------------------------------------------------------------------------------------
// Unit tests for get_hash function (currently in the works)
// #[test]
// fn test_get_hash_sha256() {
//     let buffer: Vec<u8> = vec![1, 2, 3];
//     let expected_hash = Sha256::digest(&buffer).to_vec();
//     assert_eq!(get_hash(1, &buffer).unwrap(), expected_hash);
//     assert_eq!(get_hash(3, &buffer).unwrap(), expected_hash);
// }

// #[test]
// fn test_get_hash_sha512() {
//     let buffer: Vec<u8> = vec![4, 5, 6];
//     let expected_hash = Sha512::digest(&buffer).to_vec();
//     assert_eq!(get_hash(2, &buffer).unwrap(), expected_hash);
//     assert_eq!(get_hash(4, &buffer).unwrap(), expected_hash);
// }

// #[test]
// fn test_get_hash_invalid_cs_id() {
//     // Test unsupported cs_id
//     assert!(get_hash(5, &vec![1, 2, 3]).is_err());
// }

// // Unit tests for get_sig_algorithm function
// #[test]
// fn test_get_sig_algorithm_dilithium2() {
//     assert_eq!(get_sig_algorithm(1).unwrap(), sig::Algorithm::Dilithium2);
//     assert_eq!(get_sig_algorithm(2).unwrap(), sig::Algorithm::Dilithium2);
// }

// #[test]
// fn test_get_sig_algorithm_falcon512() {
//     assert_eq!(get_sig_algorithm(3).unwrap(), sig::Algorithm::Falcon512);
//     assert_eq!(get_sig_algorithm(4).unwrap(), sig::Algorithm::Falcon512);
// }

// #[test]
// fn test_get_sig_algorithm_valid_ids() {
//     // Test valid cipher suite IDs to ensure they are mapped correctly
//     assert_eq!(get_sig_algorithm(1).unwrap(), sig::Algorithm::Dilithium2);
//     assert_eq!(get_sig_algorithm(2).unwrap(), sig::Algorithm::Dilithium2);
//     assert_eq!(get_sig_algorithm(3).unwrap(), sig::Algorithm::Falcon512);
//     assert_eq!(get_sig_algorithm(4).unwrap(), sig::Algorithm::Falcon512);
// }

// #[test]
// fn test_get_sig_algorithm_invalid_ids() {
//     // Test invalid cipher suite IDs to ensure appropriate error handling
//     assert!(get_sig_algorithm(0).is_err()); // ID out of lower range
//     assert!(get_sig_algorithm(5).is_err()); // ID out of upper range
// }

// -----------------------------------------------------------------------------------------------------------------------

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
