// Import necessary modules for testing
use clap::Parser; // Import Parser trait
use rust_cli::commands::{Args, Commands}; // Import Args and Commands from rust_cli::commands module

#[cfg(test)]
mod tests {
    // Import necessary types from the main code
    use super::*;

    /// Test parsing the "generate" command
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

    /// Test parsing the "remove" command
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

    /// Test parsing the "access" command
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

    /// Test parsing the "sign" command
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

    /// Test parsing the "verify" command
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

    /// Test parsing the hashing algorithm
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

    /// Test parsing the verification algorithm
    #[test]
    fn test_verify_algorithm() {
        // Parse command line arguments
        let args = Args::parse_from(&["test", "verify", "--name", "Alice", "--filename", "example.txt", "--signature", "abc123"]);
        // Check if the parsed command is Verify
        if let Commands::Verify { signature, .. } = args.command {
            // Check if the signature is correctly parsed
            assert_eq!(signature, "abc123".to_string());
        } else {
            panic!("Expected Verify command, found something else");
        }
    }
}
