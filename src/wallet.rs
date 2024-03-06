// A module representing a wallet that stores info about individuals and where there crypto keys are stored
// Wallet contents are stored in JSON format
// Operations include loading wallet from file, saving wallet to file, and adding and removing keys

use std::io::Read;                
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;                

// Wallet contains a hashmap with names of individuals and paths to all crypto keys associated with that name
#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    keys: HashMap<String, String>, // Maps a name to a path where the key is stored
}

impl Wallet {

    // Load wallet from file, or create a new wallet file if none found
    pub fn new() -> Self {
        Self::load_from_file("wallet.json").unwrap_or_else(|_| Wallet { keys: HashMap::new() })
    }

    // Save contents of wallet to JSON file
    pub fn save_to_file(&self, filepath: &str) -> std::io::Result<()> {
        let serialized = serde_json::to_string(&self)?;
        fs::write(filepath, serialized)?;
        Ok(())
    }

    // Load contents of wallet from JSON file
    pub fn load_from_file(filepath: &str) -> std::io::Result<Self> {
        let mut file = File::open(filepath)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let wallet = serde_json::from_str(&contents)?;
        Ok(wallet)
    }

    pub fn add_key(&mut self, name: String, path: String) {
        self.keys.insert(name, path);
    }

    pub fn remove_key(&mut self, name: &str) -> Option<String> {
        self.keys.remove(name)
    }

    // Get the path where the key is located
    pub fn get_key_path(&self, name: &str) -> Option<&String> {
        self.keys.get(name)
    }
}
