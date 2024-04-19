// A module representing a wallet that stores info about individuals and where their crypto keys are stored
// Wallet contents are stored in JSON format
// Operations include loading wallet from file, saving wallet to file, and adding and removing keys

use crate::cipher_suite::{self, CipherSuite};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// Wallet contains a hashmap with names of individuals and associated ciphersuite objects

pub struct Wallet {
    pub keys: HashMap<String, Box<dyn CipherSuite>>, // Maps a name to a ciphersuite object
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

    // Opens all persona files in wallet folder and loads them into hashmap
    pub fn load_wallet(&mut self, dir_path: String) -> std::io::Result<()> {
        for entry in fs::read_dir(dir_path)? {
            let dir = entry?;
            let content = fs::read_to_string(dir.path())?;
            let json_string = json::parse(&content).unwrap();
            let cipher_suite = cipher_suite::deserialize_ciphersuite(json_string).unwrap();
            self.keys
                .insert(cipher_suite.get_name().clone(), cipher_suite);
        }
        Ok(())
    }

    // Serializes a ciphersuite object and saves it in keys hashmap
    pub fn save_ciphersuite(&mut self, cs: Box<dyn CipherSuite>) -> std::io::Result<()> {
        let path_str = format!("wallet/{}.json", cs.get_name());
        let path = Path::new(&path_str);
        let serialized = serde_json::to_string_pretty(&cs)?;
        fs::write(path, serialized)?;
        self.keys.insert(cs.get_name().clone(), cs);
        Ok(())
    }

    // Removes a ciphersuite from local storage and keys hashmap
    pub fn remove_ciphersuite(&mut self, name: &str) -> std::io::Result<()> {
        // Convert name to lower case for case-insensitive handling
        let lower_name = name.to_lowercase();

        self.keys.remove(&lower_name);
        let path_str = format!("wallet/{}.json", lower_name);
        fs::remove_file(path_str)?;
        Ok(())
    }

    // Getter for name of persona
    pub fn get_ciphersuite(&self, name: &str) -> Option<&Box<dyn CipherSuite>> {
        self.keys.get(&name.to_lowercase())
    }
}
