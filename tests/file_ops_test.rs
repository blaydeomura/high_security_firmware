#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::time::Instant;
    use rust_cli::file_ops::{hash_file, sign_file, verify_file};
    use rust_cli::wallet::Wallet;

    const TEST_FILE: &str = "file_test_2.txt"; // Use the existing test file

    fn create_test_file() {
        let mut file = File::create(TEST_FILE).expect("Failed to create test file");
        file.write_all(b"test data").expect("Failed to write to test file");
    }

    fn remove_test_file() {
        std::fs::remove_file(TEST_FILE).expect("Failed to remove test file");
    }

    #[test]
    fn test_hash_file_blake3() {
        create_test_file();
        let start_time = Instant::now();
        hash_file(TEST_FILE, "blake3");
        let elapsed_time = start_time.elapsed();
        println!("BLAKE3 Hash Time: {:?}", elapsed_time);
        remove_test_file();
    }

    #[test]
    fn test_hash_file_sha256() {
        create_test_file();
        let start_time = Instant::now();
        hash_file(TEST_FILE, "sha256");
        let elapsed_time = start_time.elapsed();
        println!("SHA-256 Hash Time: {:?}", elapsed_time);
        remove_test_file();
    }

    #[test]
    fn test_hash_file_sha384() {
        create_test_file();
        let start_time = Instant::now();
        hash_file(TEST_FILE, "sha384");
        let elapsed_time = start_time.elapsed();
        println!("SHA-384 Hash Time: {:?}", elapsed_time);
        remove_test_file();
    }

    #[test]
    fn test_hash_file_sha512() {
        create_test_file();
        let start_time = Instant::now();
        hash_file(TEST_FILE, "sha512");
        let elapsed_time = start_time.elapsed();
        println!("SHA-512 Hash Time: {:?}", elapsed_time);
        remove_test_file();
    }

    #[test]
    fn test_sign_file() {
        let wallet = Wallet::new(); // Provide appropriate wallet initialization
        let encryption_key = b"encryption_key"; // Provide appropriate encryption key
        let signature = sign_file(&wallet, "name", TEST_FILE, encryption_key);
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_verify_file() {
        let wallet = Wallet::new(); // Provide appropriate wallet initialization
        let encryption_key = b"encryption_key"; // Provide appropriate encryption key
        let signature = sign_file(&wallet, "name", TEST_FILE, encryption_key);
        verify_file(&wallet, "name", TEST_FILE, &signature);
    }
}
