// A module representing a wallet that stores info about individuals and where their crypto keys are stored
// Wallet contents are stored in JSON format
// Operations include loading wallet from file, saving wallet to file, and adding and removing keys

use serde_json::Deserializer;

use crate::cipher_suite::CS;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Write};

// Wallet contains a hashmap with names of individuals and associated ciphersuite objects

pub struct Wallet {
    pub keys: HashMap<String, CS>, // Maps a name to a ciphersuite object
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

impl Wallet {
    // Load wallet from file, or create a new wallet file if none found
    pub fn new() -> Self {
        let keys = HashMap::new();
        Wallet { keys }
    }

    pub fn load_wallet(&mut self, wallet_path: &str) -> std::io::Result<()> {
        // Open .wallet file
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(wallet_path)?;

        // Read contents into string
        let mut buffer = String::new();
        let bytes_read = file.read_to_string(&mut buffer)?;

        // Deserialize ciphersuites
        if bytes_read > 0 {
            let stream = Deserializer::from_str(&buffer).into_iter::<CS>();
            for cs in stream {
                let cs = cs.expect("Unable to deserialize ciphersuite");
                let cs_clone = cs.clone();
                self.keys
                    .insert(cs.to_box().get_name().to_string(), cs_clone);
            }
        }

        Ok(())
    }

    pub fn save_ciphersuite(&mut self, cs: CS, wallet_path: &str) -> std::io::Result<()> {
        let mut wallet_file = OpenOptions::new().append(true).open(wallet_path)?;

        let serialized = serde_json::to_string_pretty(&cs)?;
        wallet_file.write_all(&serialized.into_bytes())?;
        wallet_file.write_all(b"\n")?;

        Ok(())
    }

    // Removes a ciphersuite from local storage and keys hashmap
    pub fn remove_ciphersuite(&mut self, name: &str, wallet_path: &str) -> std::io::Result<()> {
        let mut wallet_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(wallet_path)?;
        // Convert name to lower case for case-insensitive handling
        let lower_name = name.to_lowercase();

        // Remove from map and reserialize wallet
        self.keys.remove(&lower_name);
        let values: Vec<CS> = self.keys.values().cloned().collect();
        for cs in values {
            let serialized = serde_json::to_string_pretty(&cs)?;
            wallet_file.write_all(&serialized.into_bytes())?;
            wallet_file.write_all(b"\n")?;
        }

        Ok(())
    }

    // Getter for name of persona
    pub fn get_ciphersuite(&self, name: &str) -> Option<CS> {
        self.keys.get(&name.to_lowercase()).cloned()
    }
}
