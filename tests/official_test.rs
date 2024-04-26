// Import necessary modules for file operations, creating temporary directories, and working with cipher suites and wallets
use rust_cli::cipher_suite::{create_ciphersuite, CS};
use rust_cli::wallet::Wallet;
use std::fs::{File};
use std::io::Write;
use tempfile::tempdir;

// Define a struct to represent a cipher suite with its unique identifier, signature algorithm, and hash function
struct CipherSuite {
    cs_id: usize, // Unique identifier for the cipher suite
    signature_algorithm: &'static str, // Name of the signature algorithm used by the cipher suite
    hash_function: &'static str, // Name of the hash function used by the cipher suite
}

// Define a constant array of supported cipher suites with their respective IDs, signature algorithms, and hash functions
const CIPHER_SUITES: [CipherSuite; 5] = [
    CipherSuite {
        cs_id: 1,
        signature_algorithm: "Dilithium2", // Dilithium2 is a quantum-resistant digital signature scheme
        hash_function: "sha256", // SHA-256 is a cryptographic hash function
    },
    CipherSuite {
        cs_id: 2,
        signature_algorithm: "Dilithium2",
        hash_function: "sha512", // SHA-512 is a cryptographic hash function with a larger output size
    },
    CipherSuite {
        cs_id: 3,
        signature_algorithm: "Falcon512", // Falcon-512 is another quantum-resistant digital signature scheme
        hash_function: "sha256",
    },
    CipherSuite {
        cs_id: 4,
        signature_algorithm: "Falcon512",
        hash_function: "sha512",
    },
    CipherSuite {
        cs_id: 5,
        signature_algorithm: "RSA", // RSA is a widely-used classical digital signature scheme
        hash_function: "sha256",
    },
];

// UNIT TESTS
// -----------------------------------------------------------------------------------------------------------------------

// Test case to verify that a new cipher suite can be successfully generated for each supported algorithm
#[test]
fn test_generate_new_cipher_suite() {
    // Iterate over each cipher suite in the CIPHER_SUITES array
    for cipher_suite in &CIPHER_SUITES {
        // Create a new cipher suite with a dummy name and the current cipher suite's ID
        let cs = create_ciphersuite(String::from("Test"), cipher_suite.cs_id).unwrap();

        // Match the generated cipher suite against the expected variant based on the signature algorithm and hash function
        match cs {
            CS::CS1(_) if cipher_suite.signature_algorithm == "Dilithium2" && cipher_suite.hash_function == "sha256" => {
                assert!(true); // Assert that the expected cipher suite variant was generated
            }
            CS::CS2(_) if cipher_suite.signature_algorithm == "Dilithium2" && cipher_suite.hash_function == "sha512" => {
                assert!(true);
            }
            CS::CS3(_) if cipher_suite.signature_algorithm == "Falcon512" && cipher_suite.hash_function == "sha256" => {
                assert!(true);
            }
            CS::CS4(_) if cipher_suite.signature_algorithm == "Falcon512" && cipher_suite.hash_function == "sha512" => {
                assert!(true);
            }
            CS::CS5(_) if cipher_suite.signature_algorithm == "RSA" && cipher_suite.hash_function == "sha256" => {
                assert!(true);
            }
            _ => {
                // If the generated cipher suite does not match any of the expected variants, fail the test
                assert!(false, "Unexpected cipher suite generated");
            }
        }
    }
}

// Test case to verify the sign and verify operations for each cipher suite
#[test]
fn test_sign_and_verify() {
    // Iterate over each cipher suite in the CIPHER_SUITES array
    for cipher_suite in &CIPHER_SUITES {
        let mut wallet = Wallet::new(); // Create a new wallet instance
        let temp_dir = tempdir().unwrap(); // Create a temporary directory for testing
        let wallet_path = temp_dir.path().join("test_wallet.wallet"); // Path to the wallet file in the temporary directory

        // Create the wallet file if it doesn't exist
        let mut wallet_file = File::create(&wallet_path).unwrap();
        wallet_file.write_all(b"").unwrap(); // Write an empty byte to create the file

        // Generate a new cipher suite instance with a unique name and the current cipher suite's ID
        let cs_name = format!("test_cs_{}", cipher_suite.cs_id);
        let cs = create_ciphersuite(cs_name.clone(), cipher_suite.cs_id).unwrap();

        // Save the new cipher suite to the wallet
        wallet
            .save_ciphersuite(cs.clone(), wallet_path.to_str().unwrap())
            .unwrap();

        // Create a test file in the temporary directory
        let test_file = temp_dir.path().join("test_file.txt");
        let test_content = "Test content"; // Sample content for testing
        let mut file = File::create(&test_file).unwrap();
        file.write_all(test_content.as_bytes()).unwrap();

        // Sign the test file using the current cipher suite
        let signed_file = temp_dir.path().join("signed_test_file.txt");
        cs.clone()
            .to_box()
            .sign(test_file.to_str().unwrap(), signed_file.to_str().unwrap())
            .unwrap();

        // Verify the signed file using the current cipher suite
        cs.to_box().verify(signed_file.to_str().unwrap()).unwrap();
    }
}

// Test case to verify the removal of a cipher suite from the wallet
#[test]
fn test_remove_ciphersuite() {
    // Iterate over each cipher suite in the CIPHER_SUITES array
    for cipher_suite in &CIPHER_SUITES {
        let temp_dir = tempdir().unwrap(); // Create a temporary directory for testing
        let wallet_path = temp_dir.path().join("test_wallet.wallet"); // Path to the wallet file in the temporary directory

        // Create the wallet file if it doesn't exist
        let mut wallet_file = File::create(&wallet_path).unwrap();
        wallet_file.write_all(b"").unwrap(); // Write an empty byte to create the file

        // Prepare a unique name for the test cipher suite
        let ciphersuite_name = format!("test_ciphersuite_{}", cipher_suite.cs_id);

        let mut wallet = Wallet::new(); // Create a new wallet instance

        // Generate a new cipher suite instance with the unique name and the current cipher suite's ID
        let test_ciphersuite = create_ciphersuite(ciphersuite_name.clone(), cipher_suite.cs_id).unwrap();

        // Save the new cipher suite to the wallet
        wallet
            .save_ciphersuite(test_ciphersuite.clone(), wallet_path.to_str().unwrap())
            .unwrap();

        // Load the wallet to populate the self.keys map with the saved cipher suites
        wallet.load_wallet(wallet_path.to_str().unwrap()).unwrap();

        // Verify that the cipher suite exists in the wallet
        assert!(
            wallet.get_ciphersuite(&ciphersuite_name).is_some(),
            "Cipher suite does not exist in wallet: {}",
            ciphersuite_name
        );

        // Remove the cipher suite from the wallet
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
// PERFORMANCE TESTS

// Function to measure the performance of key generation, signing, and verification for a given cipher suite
// Returns a tuple containing the cipher suite ID, public key size, secret key size, key generation time, signing time, and verification time
fn measure_cipher_suite_performance(cipher_suite: &CipherSuite) -> (usize, usize, usize, u128, u128, u128) {
    // Measure the time taken to generate a new cipher suite instance
    let start_keygen = std::time::Instant::now(); // Start the timer
    let test_cs = create_ciphersuite(format!("cs_{}", cipher_suite.cs_id), cipher_suite.cs_id).unwrap(); // Generate a new cipher suite instance
    let end_keygen = start_keygen.elapsed().as_nanos(); // Stop the timer and calculate the elapsed time in nanoseconds
    let keygen_time_ms = end_keygen as u128 / 1_000_000; // Convert the elapsed time to milliseconds

    // Measure the time taken to sign a test file using the generated cipher suite instance
    let start_sign = std::time::Instant::now(); // Start the timer
    let mut file = tempfile::NamedTempFile::new().unwrap(); // Create a temporary file for testing
    let test_content = "Test content"; // Sample content for testing
    file.write_all(test_content.as_bytes()).unwrap(); // Write the test content to the temporary file
    let signed_file = tempfile::NamedTempFile::new().unwrap(); // Create a temporary file to store the signed content
    test_cs.clone().to_box().sign(file.path().to_str().unwrap(), signed_file.path().to_str().unwrap()).unwrap(); // Sign the test file
    let end_sign = start_sign.elapsed().as_nanos(); // Stop the timer and calculate the elapsed time in nanoseconds
    let sign_time_ms = end_sign as u128 / 1_000_000; // Convert the elapsed time to milliseconds

    // Measure the time taken to verify the signed file using the generated cipher suite instance
    let start_verify = std::time::Instant::now(); // Start the timer
    test_cs.clone().to_box().verify(signed_file.path().to_str().unwrap()).unwrap(); // Verify the signed file
    let end_verify = start_verify.elapsed().as_nanos(); // Stop the timer and calculate the elapsed time in nanoseconds
    let verify_time_ms = end_verify as u128 / 1_000_000; // Convert the elapsed time to milliseconds

    // Get the public key size and a predefined secret key size based on the cipher suite ID
    let pk_size = test_cs.to_box().get_pk_bytes().len(); // Get the size of the public key in bytes
    let sk_size = match cipher_suite.cs_id {
        1 | 2 => 2528, // Dilithium2 has a secret key size of 2528 bytes
        3 | 4 => 1281, // Falcon512 has a secret key size of 1281 bytes
        5 => 270,      // RSA has a secret key size of 270 bytes
        _ => unreachable!(), // Unreachable case, as all supported cipher suite IDs are covered
    };

    // Return the measured values as a tuple
    (cipher_suite.cs_id, pk_size, sk_size, keygen_time_ms, sign_time_ms, verify_time_ms)
}

// Test case to measure and print the performance of key generation, signing, and verification for each cipher suite
#[test]
fn test_performance() {
    println!("Performance Test Results:\n"); // Print a header for the performance test results

    // Print the table header with column names
    println!(
        "{:<5} | {:<15} | {:<15} | {:<10} | {:<10} | {:<10}| {:<10} | {:<10}",
        "ID", "Signature Algo", "Hash Function", "PK Size", "SK Size", "Keygen (ms)", "Sign (ms)", "Verify (ms)"
    );
    println!("{:-<5}-|{:-<15}- |{:-<15}- |{:-<10}- |{:-<10}- |{:-<10}- |{:-<10}- |{:-<10}", "-", "-", "-", "-", "-", "-", "-", "-");

    // Iterate over each cipher suite in the CIPHER_SUITES array
    for cipher_suite in &CIPHER_SUITES {
        // Measure the performance of key generation, signing, and verification for the current cipher suite
        let (cs_id, pk_size, sk_size, keygen_time_ms, sign_time_ms, verify_time_ms) = measure_cipher_suite_performance(cipher_suite);

        // Print the performance results for the current cipher suite
        println!(
            "{:<5} | {:<15} | {:<15} | {:<10} | {:<10} | {:<10} | {:<10} | {:<10}",
            cs_id, cipher_suite.signature_algorithm, cipher_suite.hash_function, pk_size, sk_size, keygen_time_ms, sign_time_ms, verify_time_ms
        );
    }
}
// -----------------------------------------------------------------------------------------------------------------------