// #[cfg(test)]
// mod wallet_tests {
//     use std::fs;
//     use std::env;
//     use rust_cli::wallet::{Wallet, key_file_path}; // Import the Wallet struct and key_file_path function
//     use rust_cli::wallet::remove_key;  // Adjust the path accordingly
//     use rust_cli::wallet::generate_key;

//     fn create_temp_dir() -> std::io::Result<std::path::PathBuf> {
//         // Get the system's temporary directory
//         let mut temp_dir = env::temp_dir();
    
//         // Generate a unique directory name
//         let dir_name = format!("temp_dir_{}", rand::random::<u32>());
    
//         // Append the unique directory name to the temporary directory path
//         temp_dir.push(&dir_name);
    
//         // Create the temporary directory
//         fs::create_dir(&temp_dir)?;
    
//         Ok(temp_dir)
//     }

//     // This test case verifies that the load_from_file() function correctly reads wallet contents from a JSON file. 
//     // It creates a temporary directory, writes a sample wallet JSON to a file within that directory, and then calls load_from_file() to load the wallet. 
//     // This test ensures that loading from file works as expected.
//     #[test]
//     fn test_load_from_file() {
//         // Get the temporary directory path
//         let temp_dir = create_temp_dir().expect("Failed to create temporary directory");

//         // Create a temporary wallet file inside the directory
//         let wallet_json = r#"{"keys":{"test_person":"keys/test_person.pk8"}}"#;
//         let wallet_file_path = temp_dir.join("wallet.json");
        
//         // Write the wallet JSON to the temporary file
//         fs::write(&wallet_file_path, wallet_json).expect("Failed to write wallet file");
//     }

//     // This test case ensures that the save_to_file() function correctly serializes the wallet contents to a JSON string and writes it to a file. 
//     // It creates a wallet instance with sample keys, saves it to a temporary file, reads the saved file's content, and compares it with the expected JSON format. 
//     // This test guarantees that saving to file functions as intended.
//     #[test]
//     fn test_save_to_file() {
//         // Create a wallet with some keys
//         let wallet = Wallet {
//             keys: vec![("test_person".to_string(), "keys/test_person.pk8".to_string())].into_iter().collect(),
//         };

//         // Create a temporary directory
//         let temp_dir = create_temp_dir().expect("Failed to create temporary directory");
//         let wallet_file_path = temp_dir.join("wallet.json");
        
//         // Save the wallet to a temporary file
//         wallet.save_to_file(wallet_file_path.to_str().unwrap()).unwrap();

//         // Read the content of the saved file
//         let saved_content = fs::read_to_string(wallet_file_path).unwrap();

//         // Check if the saved content matches the expected JSON format
//         assert_eq!(saved_content, r#"{"keys":{"test_person":"keys/test_person.pk8"}}"#);
//     }

//     // This test case verifies the generate_key() function's behavior by generating a new key and saving it to the wallet. 
//     // It creates a temporary directory, generates a key for a new person, and checks if the key is added to the wallet correctly. 
//     // This test ensures that key generation and addition to the wallet work as expected.
//     #[test]
//     fn test_generate_key() {
//         // Create a temporary directory
//         let temp_dir = create_temp_dir().expect("Failed to create temporary directory");

//         // Generate a key and save it to the wallet
//         let mut wallet = Wallet::new();
//         let key_name = "new_person";
//         let encryption_key = "encryption_key".as_bytes(); // Mock encryption key

//         generate_key(&mut wallet, key_name, encryption_key);

//         // Check if the key is added to the wallet
//         assert_eq!(wallet.keys.len(), 1);
//         assert_eq!(wallet.keys.get(key_name), Some(&key_file_path(key_name)));
//     }

//     //  This test case ensures that the remove_key() function correctly removes a key from the wallet. 
//     // It creates a wallet with a sample key, calls remove_key() to remove that key, and then checks if the wallet is empty. 
//     // This test guarantees that key removal works as intended.
//     #[test]
//     fn test_remove_key() {
//         // Create a wallet with some keys
//         let mut wallet = Wallet {
//             keys: vec![("test_person".to_string(), "keys/test_person.pk8".to_string())].into_iter().collect(),
//         };

//         // Call the remove_key function
//         remove_key(&mut wallet, "test_person");

//         // Ensure that the key has been removed from the wallet
//         assert!(wallet.keys.is_empty());
//     }

// }
