// Import necessary modules
use rust_cli::cipher_suite::{create_ciphersuite, CS};
use rust_cli::wallet::Wallet;
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;


#[test]
fn test_generate_new_cipher_suite() {
    // Test generating a new cipher suite for each supported algorithm
    for i in 1..=5 {
        let cs = create_ciphersuite(String::from("Test"), i).unwrap();
        match cs {
            CS::CS1(_) | CS::CS2(_) | CS::CS3(_) | CS::CS4(_) | CS::CS5(_) => {
                // Ensure that the cipher suite is generated successfully
                assert!(true);
            }
        }
    }
}
#[test]
fn test_sign_and_verify() {
    for cs_id in 1..=5 {
        let mut wallet = Wallet::new();
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet.wallet");

        // Create the wallet file if it doesn't exist
        let mut wallet_file = File::create(&wallet_path).unwrap();
        wallet_file.write_all(b"").unwrap(); // Write an empty byte to create the file

        // Generate a new key pair
        let cs_name = format!("test_cs_{}", cs_id);
        let cs = create_ciphersuite(cs_name.clone(), cs_id).unwrap();
        wallet
            .save_ciphersuite(cs.clone(), wallet_path.to_str().unwrap())
            .unwrap();

        // Create a test file
        let test_file = temp_dir.path().join("test_file.txt");
        let test_content = "Test content";
        let mut file = File::create(&test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        // Sign the test file
        let signed_file = temp_dir.path().join("signed_test_file.txt");
        cs.clone()
            .to_box()
            .sign(test_file.to_str().unwrap(), signed_file.to_str().unwrap())
            .unwrap();

        // Verify the signed file
        cs.to_box().verify(signed_file.to_str().unwrap()).unwrap();
    }
}

#[test]
fn test_remove_ciphersuite() {
    for cs_id in 1..=5 {
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet.wallet");

        // Create the wallet file if it doesn't exist
        let mut wallet_file = File::create(&wallet_path).unwrap();
        wallet_file.write_all(b"").unwrap(); // Write an empty byte to create the file

        // Prepare test data
        let ciphersuite_name = format!("test_ciphersuite_{}",cs_id);

        // Create wallet and add cipher suite
        let mut wallet = Wallet::new();
        let test_ciphersuite = create_ciphersuite(ciphersuite_name.clone(), cs_id).unwrap();
        wallet
            .save_ciphersuite(test_ciphersuite.clone(), wallet_path.to_str().unwrap())
            .unwrap();

        // Load the wallet to populate the self.keys map
        wallet.load_wallet(wallet_path.to_str().unwrap()).unwrap();

        // Verify that the cipher suite exists in the wallet
        assert!(
            wallet.get_ciphersuite(&ciphersuite_name).is_some(),
            "Cipher suite does not exist in wallet: {}",
            ciphersuite_name
        );

        // Remove cipher suite from wallet
        wallet
            .remove_ciphersuite(&ciphersuite_name, wallet_path.to_str().unwrap())
            .unwrap();

        // Verify that the cipher suite is removed from the wallet
        assert!(
            wallet.get_ciphersuite(&ciphersuite_name).is_none(),
            "Cipher suite still exists in wallet after removal: {}",
            ciphersuite_name
        );
    }
}


// -----------------------------------------------------------------------------------------------------------------------
// PERFORMANCE TEST 
fn measure_cipher_suite_performance(cs_id: usize) -> (String, Vec<(u128, usize)>) {
    let mut measurements = Vec::new();
    let mut wallet = Wallet::new();
    let cs_name = format!("test_cs_{}", cs_id);
    let test_cs = create_ciphersuite(cs_name.clone(), cs_id).unwrap();
    let wallet_path = format!("test_wallet_{}.json", cs_id);
    fs::create_dir_all(std::path::Path::new(&wallet_path).parent().unwrap()).expect("Failed to create directory");
    wallet
        .save_ciphersuite(test_cs.clone(), &wallet_path)
        .unwrap();

    // Measure the performance of each operation
    let start_sign = std::time::Instant::now();
    let cs_box = test_cs.clone().to_box();
    let _sign_result = cs_box.sign("files/file_test.txt", "output_signature_file_path");
    let end_sign = start_sign.elapsed().as_nanos();
    let sign_time_ms = end_sign as u128 / 1_000_000;
    let sign_pk_size = test_cs.clone().to_box().get_pk_bytes().len();
    measurements.push((sign_time_ms, sign_pk_size));

    let start_verify = std::time::Instant::now();
    let _verify_result = cs_box.verify("signatures/test_cs_1_file_test.txt.sig");
    let end_verify = start_verify.elapsed().as_nanos();
    let verify_time_ms = end_verify as u128 / 1_000_000;
    let verify_pk_size = test_cs.clone().to_box().get_pk_bytes().len();
    measurements.push((verify_time_ms, verify_pk_size));

    let start_remove = std::time::Instant::now();
    let _remove_result = wallet.remove_ciphersuite(&cs_name, "test_wallet.json");
    let end_remove = start_remove.elapsed().as_nanos();
    let remove_time_ms = end_remove as u128 / 1_000_000;
    let remove_pk_size = test_cs.clone().to_box().get_pk_bytes().len();
    measurements.push((remove_time_ms, remove_pk_size));

    (format!("Cipher Suite {}", cs_id), measurements)
}

#[test]
fn test_performance() {
    // Print table header
    println!("Performance Test Results:");
    println!(
        "{:<20} | {:<15} | {:<10} | {:<15}",
        "Cipher Suite", "Operation", "Time (ms)", "Public Key Size"
    );
    println!("{:-<20}-|{:-<15}-|{:-<10}-|{:-<15}", "", "", "", "");

    // Iterate through each cipher suite and measure performance
    for cs_id in 1..=5 {
        let (suite_name, measurements) = measure_cipher_suite_performance(cs_id);

        // Print results for each operation and cipher suite
        for (operation, (time_ms, pk_size)) in measurements.iter().enumerate() {
            let operation_name = match operation {
                0 => "Sign",
                1 => "Verify",
                2 => "Remove",
                _ => unreachable!(), // Just to handle potential future additions to measurements
            };
            println!(
                "{:<20} | {:<15} | {:<10} | {:<15}",
                suite_name, operation_name, time_ms, pk_size
            );
        }
    }
}


// // -----------------------------------------------------------------------------------------------------------------------
// // EDGE CASE TESTS 

// #[test]
// fn test_sign_and_verify_empty_file() {
//     let mut wallet = Wallet::new();
//     let dir = tempdir().unwrap();
//     let file_path = dir.path().join("empty_file.txt");
//     fs::File::create(&file_path).expect("Failed to create empty file");

//     let cs_name = "TestCSEmpty";
//     let cs_id = 1;
//     let cs = create_ciphersuite(cs_name.to_string(), cs_id).unwrap();
//     let wallet_path = dir.path().join("test_wallet.json");
//     fs::create_dir_all(wallet_path.parent().unwrap()).expect("Failed to create directory");
//     wallet
//         .save_ciphersuite(cs.clone(), wallet_path.to_str().unwrap())
//         .expect("Failed to save cipher suite");

//     let signature_file = dir.path().join("signature_file_empty.txt");

//     // Sign empty file
//     let cs_box = cs.to_box();
//     cs_box
//         .sign(
//             &file_path.to_str().unwrap(),
//             &signature_file.to_str().unwrap(),
//         )
//         .expect("Failed to sign empty file");

//     // Verify signature against the empty file
//     cs_box.verify(&signature_file.to_str().unwrap()).expect("Failed to verify empty file");
// }

// #[test]
// fn test_sign_and_verify_file_with_multiple_signatures() {
//     let mut wallet = Wallet::new();
//     let dir = tempdir().unwrap();
//     let file_path = dir.path().join("file_test_multiple_signatures.txt");
//     fs::write(&file_path, "Test file content").expect("Failed to write file content");

//     let cs_names = vec!["TestCS1", "TestCS2", "TestCS3"];
//     let cs_ids = vec![1, 2, 3];

//     let mut signature_files = Vec::new();

//     for (cs_name, cs_id) in cs_names.iter().zip(cs_ids.iter()) {
//         let cs = create_ciphersuite(cs_name.to_string(), *cs_id).unwrap();
//         wallet
//             .save_ciphersuite(cs.clone(), "test_wallet.json")
//             .expect("Failed to save cipher suite");

//         let signature_file = dir
//             .path()
//             .join(format!("signature_file_{}.txt", cs_name));
//         signature_files.push(signature_file.clone());

//         // Sign file with each cipher suite
//         let cs_box = cs.to_box();
//         cs_box
//             .sign(
//                 &file_path.to_str().unwrap(),
//                 &signature_file.to_str().unwrap(),
//             )
//             .expect("Failed to sign file");
//     }

//     // Verify all signatures against the file
//     for (cs_name, signature_file) in cs_names.iter().zip(signature_files.iter()) {
//         let cs = wallet.get_ciphersuite(cs_name).unwrap();
//         let cs_box = cs.to_box();
//         cs_box.verify(&signature_file.to_str().unwrap()).expect("Failed to verify signature");
//     }
// }

// #[test]
// #[should_panic(expected = "Verification failed: invalid file contents")]
// fn test_verify_with_tampered_signature() {
//     let mut wallet = Wallet::new();
//     let dir = tempdir().unwrap();
//     let file_path = dir.path().join("file_test.txt");
//     fs::write(&file_path, "Test file content").expect("Failed to write file content");

//     let cs_name = "TestCSTampered";
//     let cs_id = 1;
//     let cs = create_ciphersuite(cs_name.to_string(), cs_id).unwrap();
//     wallet
//         .save_ciphersuite(cs.clone(), "test_wallet.json")
//         .expect("Failed to save cipher suite");

//     let signature_file = dir.path().join("signature_file_tampered.txt");
//     let cs_box = cs.to_box();
//     cs_box
//         .sign(
//             &file_path.to_str().unwrap(),
//             &signature_file.to_str().unwrap(),
//         )
//         .expect("Failed to sign file");

//     // Tamper with the file content
//     fs::write(&file_path, "Tampered file content").expect("Failed to tamper file content");

//     // Attempt to verify with the tampered file
//     cs_box.verify(&signature_file.to_str().unwrap()).unwrap();
// }

// #[test]
// #[should_panic(expected = "not found in the wallet")]
// fn test_sign_with_non_existent_ciphersuite() {
//     let _wallet = Wallet::new();
//     let dir = tempdir().unwrap();
//     let file_path = dir.path().join("file_test.txt");
//     fs::write(&file_path, "Test file content").expect("Failed to write file content");

//     let cs_name = "NonExistentCS";
//     let cs_id = 1;
//     let cs = create_ciphersuite(cs_name.to_string(), cs_id).unwrap();

//     let signature_file = dir.path().join("signature_file_non_existent.txt");

//     // Attempt to sign with a non-existent cipher suite
//     let cs_box = cs.to_box();
//     cs_box
//         .sign(
//             &file_path.to_str().unwrap(),
//             &signature_file.to_str().unwrap(),
//         )
//         .unwrap();
// }

// #[test]
// fn test_sign_and_verify_large_file() {
//     let mut wallet = Wallet::new();
//     let dir = tempdir().unwrap();
//     let file_path = dir.path().join("large_file.txt");
//     let large_content = "a".repeat(1024 * 1024 * 10); // 10MB file
//     fs::write(&file_path, large_content).expect("Failed to write large file content");

//     let cs_name = "TestCSLarge";
//     let cs_id = 1;
//     let cs = create_ciphersuite(cs_name.to_string(), cs_id).unwrap();
//     wallet
//         .save_ciphersuite(cs.clone(), "test_wallet.json")
//         .expect("Failed to save cipher suite");

//     let signature_file = dir.path().join("signature_file_large.txt");

//     // Sign large file
//     let cs_box = cs.to_box();
//     cs_box
//         .sign(
//             &file_path.to_str().unwrap(),
//             &signature_file.to_str().unwrap(),
//         )
//         .expect("Failed to sign large file");

//     // Verify signature against the large file
//     cs_box.verify(&signature_file.to_str().unwrap()).expect("Failed to verify large file");
// }