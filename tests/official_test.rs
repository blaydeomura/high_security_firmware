// Import necessary modules
use rust_cli::cipher_suite::{create_ciphersuite, CS};
use rust_cli::wallet::Wallet;
use std::fs::{File};
use std::io::Write;
use tempfile::tempdir;

struct CipherSuite {
    cs_id: usize,
    signature_algorithm: &'static str,
    hash_function: &'static str,
}

const CIPHER_SUITES: [CipherSuite; 5] = [
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
    CipherSuite {
        cs_id: 5,
        signature_algorithm: "RSA",
        hash_function: "sha256",
    },
];

#[test]
fn test_generate_new_cipher_suite() {
    for cipher_suite in &CIPHER_SUITES {
        let cs = create_ciphersuite(String::from("Test"), cipher_suite.cs_id).unwrap();
        match cs {
            CS::CS1(_) if cipher_suite.signature_algorithm == "Dilithium2" && cipher_suite.hash_function == "sha256" => {
                assert!(true);
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
                assert!(false, "Unexpected cipher suite generated");
            }
        }
    }
}

#[test]
fn test_sign_and_verify() {
    for cipher_suite in &CIPHER_SUITES {
        let mut wallet = Wallet::new();
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet.wallet");

        // Create the wallet file if it doesn't exist
        let mut wallet_file = File::create(&wallet_path).unwrap();
        wallet_file.write_all(b"").unwrap(); // Write an empty byte to create the file

        // Generate a new key pair
        let cs_name = format!("test_cs_{}", cipher_suite.cs_id);
        let cs = create_ciphersuite(cs_name.clone(), cipher_suite.cs_id).unwrap();
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
    for cipher_suite in &CIPHER_SUITES {
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("test_wallet.wallet");

        // Create the wallet file if it doesn't exist
        let mut wallet_file = File::create(&wallet_path).unwrap();
        wallet_file.write_all(b"").unwrap(); // Write an empty byte to create the file

        // Prepare test data
        let ciphersuite_name = format!("test_ciphersuite_{}", cipher_suite.cs_id);

        // Create wallet and add cipher suite
        let mut wallet = Wallet::new();
        let test_ciphersuite = create_ciphersuite(ciphersuite_name.clone(), cipher_suite.cs_id).unwrap();
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