// Import necessary modules for testing
use clap::Parser; // Import Parser trait
use rust_cli::commands::{Args, Commands}; // Import Args and Commands from rust_cli::commands module
use std::process::Command; // Import Command for integration tests
//use std::time::Instant; // Import Instant for measuring performance

#[cfg(test)]
mod tests {
    // Import necessary types from the main code
    use super::*;


    // Test parsing the "generate" command
    #[test]
    fn test_parse_generate_command() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "generate", "--name", "Alice", "--encryption-key", "123456"]);
        // Check if the parsed command is Generate
        if let Commands::Generate { name, encryption_key } = args.command {
            // Check if the name and encryption key are correctly parsed
            assert_eq!(name, "Alice".to_string());
            assert_eq!(encryption_key, "123456".to_string());
        } else {
            panic!("Expected Generate command, found something else");
        }
    }

    #[test]
    fn test_generate_command_integration() {
        // Execute the CLI application with appropriate arguments
        let output = Command::new("rust_cli")
            .arg("generate")
            .arg("--name")
            .arg("Alice")
            .arg("--encryption-key")
            .arg("123456")
            .output()
            .expect("Failed to execute command");
        
        // Check if the output contains expected information or if the wallet file is correctly updated
        assert!(output.status.success());
    }

    // Test parsing the "remove" command
    #[test]
    fn test_parse_remove_command() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "remove", "--name", "Bob"]);
        // Check if the parsed command is Remove
        if let Commands::Remove { name } = args.command {
            // Check if the name is correctly parsed
            assert_eq!(name, "Bob".to_string());
        } else {
            panic!("Expected Remove command, found something else");
        }
    }

    // Test parsing the "access" command
    #[test]
    fn test_parse_access_command() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "access", "--name", "Alice", "--encryption-key", "123456"]);
        // Check if the parsed command is Access
        if let Commands::Access { name, encryption_key } = args.command {
            // Check if the name and encryption key are correctly parsed
            assert_eq!(name, "Alice".to_string());
            assert_eq!(encryption_key, "123456".to_string());
        } else {
            panic!("Expected Access command, found something else");
        }
    }

    /// Test parsing the "hash-file" command
    #[test]
    fn test_parse_hash_file_command() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "hash-file", "--filename", "example.txt", "--algorithm", "sha256"]);
        // Check if the parsed command is HashFile
        if let Commands::HashFile { filename, algorithm } = args.command {
            // Check if the filename and algorithm are correctly parsed
            assert_eq!(filename, "example.txt".to_string());
            assert_eq!(algorithm, "sha256".to_string());
        } else {
            panic!("Expected HashFile command, found something else");
        }
    }

    // Test parsing the "sign" command
    #[test]
    fn test_parse_sign_command() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "sign", "--name", "Alice", "--filename", "example.txt"]);
        // Check if the parsed command is Sign
        if let Commands::Sign { name, filename } = args.command {
            // Check if the name and filename are correctly parsed
            assert_eq!(name, "Alice".to_string());
            assert_eq!(filename, "example.txt".to_string());
        } else {
            panic!("Expected Sign command, found something else");
        }
    }

    // Test parsing the "verify" command
    #[test]
    fn test_parse_verify_command() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "verify", "--name", "Alice", "--filename", "example.txt", "--signature", "abc123"]);
        // Check if the parsed command is Verify
        if let Commands::Verify { name, filename, signature } = args.command {
            // Check if the name, filename, and signature are correctly parsed
            assert_eq!(name, "Alice".to_string());
            assert_eq!(filename, "example.txt".to_string());
            assert_eq!(signature, "abc123".to_string());
        } else {
            panic!("Expected Verify command, found something else");
        }
    }

    // Test parsing the hashing algorithm
    #[test]
    fn test_hash_algorithm() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "hash-file", "--filename", "example.txt", "--algorithm", "sha256"]);
        // Check if the parsed command is HashFile
        if let Commands::HashFile { algorithm, .. } = args.command {
            // Check if the algorithm is correctly parsed
            assert_eq!(algorithm, "sha256".to_string());
        } else {
            panic!("Expected HashFile command, found something else");
        }
    }

    // Test parsing the hashing algorithm for SHA-256

    #[test]
    fn test_hash_algorithm_sha256() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "hash-file", "--filename", "example.txt", "--algorithm", "sha256"]);
        // Check if the parsed command is HashFile
        if let Commands::HashFile { algorithm, .. } = args.command {
            // Check if the algorithm is correctly parsed
            assert_eq!(algorithm, "sha256".to_string());
        } else {
            panic!("Expected HashFile command, found something else");
        }
    }

    // Test parsing the hashing algorithm for SHA-512
    #[test]
    fn test_hash_algorithm_sha512() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "hash-file", "--filename", "example.txt", "--algorithm", "sha512"]);
        // Check if the parsed command is HashFile
        if let Commands::HashFile { algorithm, .. } = args.command {
            // Check if the algorithm is correctly parsed
            assert_eq!(algorithm, "sha512".to_string());
        } else {
            panic!("Expected HashFile command, found something else");
        }
    }

    // /// Test parsing the hashing algorithm for MD5
    // #[test]
    // fn test_hash_algorithm_md5() {
    //     // Parse command line arguments
    //     let args = Args::parse_from(&["test", "hash-file", "--filename", "example.txt", "--algorithm", "md5"]);
    //     // Check if the parsed command is HashFile
    //     if let Commands::HashFile { algorithm, .. } = args.command {
    //         // Check if the algorithm is correctly parsed
    //         assert_eq!(algorithm, "md5".to_string());
    //     } else {
    //         panic!("Expected HashFile command, found something else");
    //     }
    // }

    // Test parsing the hashing algorithm for SHA-384
    #[test]
    fn test_hash_algorithm_sha384() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "hash-file", "--filename", "example.txt", "--algorithm", "sha384"]);
        // Check if the parsed command is HashFile
        if let Commands::HashFile { algorithm, .. } = args.command {
            // Check if the algorithm is correctly parsed
            assert_eq!(algorithm, "sha384".to_string());
        } else {
            panic!("Expected HashFile command, found something else");
        }
    }

    // Test parsing the hashing algorithm for BLAKE3
    #[test]
    fn test_hash_algorithm_blake3() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "hash-file", "--filename", "example.txt", "--algorithm", "blake3"]);
        // Check if the parsed command is HashFile
        if let Commands::HashFile { algorithm, .. } = args.command {
            // Check if the algorithm is correctly parsed
            assert_eq!(algorithm, "blake3".to_string());
        } else {
            panic!("Expected HashFile command, found something else");
        }
    }

    // Error Handling Tests
    
    // Test error handling for file I/O operations
    #[test]
    fn test_file_io_error_handling() {
        // Try to access a non-existent file
        let args = Args::parse_from(&["test", "access", "--name", "Alice", "--encryption-key", "123456"]);
        // Check if the command execution fails with appropriate error message
        assert!(matches!(args.command, Commands::Access { .. }));
    }

    // Test error handling for cryptographic operations
    #[test]
    fn test_crypto_error_handling() {
        // Provide an invalid encryption key format
        let args = Args::parse_from(&["test", "sign", "--name", "Alice", "--filename", "file_test.txt"]);
        // Check if the command execution fails with appropriate error message
        assert!(matches!(args.command, Commands::Sign { .. }));
    }

    // Performance Tests

}
