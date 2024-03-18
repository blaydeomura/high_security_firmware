// A module representing a wallet that stores info about individuals and where their crypto keys are stored
// Wallet contents are stored in JSON format
// Operations include loading wallet from file, saving wallet to file, and adding and removing keys

// use std::fs;
// use std::fs::File;
// use std::io::Read;                
// use std::path::{Path, PathBuf};                         
// use std::collections::HashMap;
// use serde::{Deserialize, Serialize};
// use base64::{Engine as _, engine::general_purpose};
// use aes_gcm::{Aes256Gcm, Nonce, KeyInit}; 
// use aes_gcm::aead::Aead; 
// use aes_gcm::aead::generic_array::GenericArray;
// use ::rand::Rng;
// use ::rand::rngs::OsRng;
// use ring::signature::{Ed25519KeyPair, KeyPair};
// use super::error::MyError;
// use super::persona::Persona;
use std::fs;            
use std::path::Path;                         
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::persona::Persona;

// Wallet contains a hashmap with names of individuals and associated persona objects
#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
   pub keys: HashMap<String, Persona>, // Maps a name to a persona object
}

impl Wallet {
    // Load wallet from file, or create a new wallet file if none found
    pub fn new() -> Self {
        let keys = Wallet::load_wallet("wallet");
        Wallet {
            keys: keys.unwrap()
        }
    }

    pub fn load_wallet(dir_path: &str) -> std::io::Result<HashMap<String, Persona>> {
        let mut keys = HashMap::new();
        for entry in fs::read_dir(dir_path)? {
            let dir = entry?;
            let content = fs::read_to_string(dir.path())?;
            let persona: Persona = serde_json::from_str(&content).unwrap();
            keys.insert(persona.get_name(), persona);
        }

        Ok(keys)
    }

    pub fn save_persona(&mut self, persona: Persona) -> std::io::Result<()> {
        let path_str = format!("wallet/{}.json", persona.get_name());
        let path = Path::new(&path_str);
        let serialized = serde_json::to_string(&persona)?;
        fs::write(path, serialized)?;
        self.keys.insert(persona.get_name(), persona);
        Ok(())
    }

    pub fn remove_persona(&mut self, name: &String) -> std::io::Result<()> {
        self.keys.remove(name);
        let path_str = format!("wallet/{}.json", name);
        fs::remove_file(path_str)?;
        Ok(())
    }

    pub fn get_persona(&self, name: &str) -> Option<&Persona> {
        self.keys.get(name)
    }

    // // Save contents of wallet to JSON file
    // pub fn save_to_file(&self, filepath: &str) -> std::io::Result<()> {
    //     let serialized = serde_json::to_string(&self)?;
    //     fs::write(filepath, serialized)?;
    //     Ok(())
    // }

    // // Load contents of wallet from JSON file
    // pub fn load_from_file(filepath: &str) -> std::io::Result<Self> {
    //     let mut file = File::open(filepath)?;
    //     let mut contents = String::new();
    //     file.read_to_string(&mut contents)?;
    //     let wallet = serde_json::from_str(&contents)?;
    //     Ok(wallet)
    // }

    // pub fn add_key(&mut self, name: String, path: String) {
    //     self.keys.insert(name, path);
    // }

    // pub fn remove_key(&mut self, name: &str) -> Option<String> {
    //     self.keys.remove(name)
    // }

    // // Get the path where the key is located
    // pub fn get_key_path(&self, name: &str) -> Option<&String> {
    //     self.keys.get(name)
    // }
}

// // Format path to key file
// pub fn key_file_path(name: &str) -> String {
//     format!("keys/{}.pk8", name)
// }

// // Generate a public and private key for a given name
// // Save wallet contents to file
// pub fn generate_key(wallet: &mut Wallet, name: &str, encryption_key: &[u8]) {
//     let path_str = key_file_path(name);
//     let path = Path::new(&path_str);

//     if wallet.get_key_path(name).is_some() {
//         println!("A key pair already exists for {}.", name);
//         return;
//     }

//     match generate_and_save_key_pair(path, encryption_key) {
//         Ok(_) => {
//             println!("Key pair generated and saved successfully for {}.", name);
//             wallet.add_key(name.to_string(), path_str);
//             wallet.save_to_file("wallet.json").expect("Failed to save wallet.");
//         },
//         Err(e) => eprintln!("Failed to generate and save key pair for {}: {}", name, e),
//     }
// }

// // Helper function to generate key pair and write key pair to a file
// fn generate_and_save_key_pair(path: &Path, encryption_key: &[u8]) -> Result<(), MyError> {
//     let rng = ring::rand::SystemRandom::new();
//     let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
//         .map_err(MyError::from)?;

//     let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
//         .map_err(MyError::from)?;

//     // Encrypt and save the private key
//     let encrypted_data = encrypt_data(pkcs8_bytes.as_ref(), encryption_key);
//     fs::write(path, &encrypted_data)
//         .map_err(|_e| MyError::Unspecified(ring::error::Unspecified {}))?; // You need a way to convert io::Error to MyError

//     // Save the public key
//     let public_key_bytes = key_pair.public_key().as_ref();
//     let public_key_path = path.with_extension("pub.pk8");
//     fs::write(public_key_path, public_key_bytes)
//         .map_err(|_e| MyError::Unspecified(ring::error::Unspecified {}))?; // Same here

//     Ok(())
// }

// // Remove a key from the wallet
// pub fn remove_key(wallet: &mut Wallet, name: &str) {
//     if let Some(path_str) = wallet.remove_key(name) {
//         // Convert the private key path from String to PathBuf
//         let private_key_path = PathBuf::from(path_str);
        
//         // Attempt to remove the private key file
//         if fs::remove_file(&private_key_path).is_ok() {
//             println!("Private key file for {} has been removed.", name);
//         } else {
//             eprintln!("Failed to remove private key file for {}.", name);
//         }

//         // Construct the path for the public key file by changing the extension
//         let public_key_path = private_key_path.with_extension("pub.pk8");
        
//         // Attempt to remove the public key file
//         if fs::remove_file(&public_key_path).is_ok() {
//             println!("Public key file for {} has been removed.", name);
//         } else {
//             eprintln!("Failed to remove public key file for {}.", name);
//         }
//     } else {
//         println!("No key file found for {}.", name);
//     }
// }

// // Prints key associated with a given name
// pub fn access_key(wallet: &Wallet, name: &str, encryption_key: &[u8]) {
//     if let Some(path_str) = wallet.get_key_path(name) {
//         let path = Path::new(path_str);
//         match fs::read(path) {
//             Ok(encrypted_data) => {
//                 let decrypted_data = decrypt_data(&encrypted_data, encryption_key);
//                 // let b64_contents = base64::encode(&decrypted_data);
//                 let b64_contents = general_purpose::STANDARD.encode(&decrypted_data);

//                 println!("Decrypted key for {} (Base64 encoded):\n{}", name, b64_contents);
//             },
//             Err(_) => println!("Error: No key file found for {}.", name),
//         }
//     } else {
//         println!("No key file found for {}.", name);
//     }
// }

// // Encrypts data with AES-GCM library with a provided key
// // NEEDS UPDATE TO MORE SECURE
// fn encrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
//     let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

//     // Create the nonce and store it in a variable to extend its lifetime
//     let nonce_array = OsRng.gen::<[u8; 12]>();  // Generate a random nonce
//     let nonce = Nonce::from_slice(&nonce_array); // Convert the array into a Nonce type
    
//     let encrypted_data = cipher.encrypt(nonce, data.as_ref())
//         .expect("encryption failure");
    
//     // Prepend nonce to encrypted data
//     [nonce.as_slice(), encrypted_data.as_slice()].concat()
// }

// // Decrypt key using AES256-GCM
// pub fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
//     let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
//     let (nonce, ciphertext) = encrypted_data.split_at(12);
//     cipher.decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
//         .expect("decryption failure")
// }
