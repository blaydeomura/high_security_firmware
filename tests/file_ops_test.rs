use rust_cli::wallet::Wallet;
use rust_cli::file_ops::{sign, verify};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_signature_generation_and_verification() {
    let wallet = Wallet::new();

    let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    temp_file.write_all(b"Test data").expect("Failed to write to file");
    let file_path = temp_file.path().to_str().expect("Failed to get file path");

    sign("test_persona", file_path, &wallet).expect("Failed to generate signature");

    // Define a temporary signature file path for verification
    let mut signature_temp_file = NamedTempFile::new().expect("Failed to create temporary signature file");
    let signature_file_path = signature_temp_file.path().to_str().expect("Failed to get signature file path");

    verify("test_persona", file_path, signature_file_path, &wallet).expect("Failed to verify signature");
}

#[test]
fn test_signature_generation_performance() {
    let wallet = Wallet::new();

    let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    let data = vec![0u8; 10 * 1024 * 1024]; // 10 MB
    temp_file.write_all(&data).expect("Failed to write to file");
    let file_path = temp_file.path().to_str().expect("Failed to get file path");

    let start_time = std::time::Instant::now();
    sign("test_persona", file_path, &wallet).expect("Failed to generate signature");
    let elapsed_time = start_time.elapsed();

    assert!(elapsed_time < std::time::Duration::from_secs(10), "Signature generation took too long");
}

#[test]
fn test_signature_verification_performance() {
    let wallet = Wallet::new();

    let mut temp_file = NamedTempFile::new().expect("Failed to create temporary file");
    let data = vec![0u8; 10 * 1024 * 1024]; // 10 MB
    temp_file.write_all(&data).expect("Failed to write to file");
    let file_path = temp_file.path().to_str().expect("Failed to get file path");

    sign("test_persona", file_path, &wallet).expect("Failed to generate signature");

    // Define a temporary signature file path for verification
    let mut signature_temp_file = NamedTempFile::new().expect("Failed to create temporary signature file");
    let signature_file_path = signature_temp_file.path().to_str().expect("Failed to get signature file path");

    let start_time = std::time::Instant::now();
    verify("test_persona", file_path, signature_file_path, &wallet).expect("Failed to verify signature");
    let elapsed_time = start_time.elapsed();

    assert!(elapsed_time < std::time::Duration::from_secs(10), "Signature verification took too long");
}
