// Import the necessary modules and types
use rust_cli::wallet::Wallet;
use rust_cli::file_ops::{sign, verify};
use rust_cli::persona::Persona;
use std::path::Path;

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
