use std::io::Read;                
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;                

// Struct for wallet: stores keys mapped to names
// HashMap: Key = Key of person (String), Value = Path where key is stored (String)
#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    keys: HashMap<String, String>, // Maps a name to a path where the key is stored
}

impl Wallet {

    pub fn new() -> Self {
        // Try to load the wallet from a file, or create a new one if it doesn't exist
        Self::load_from_file("wallet.json").unwrap_or_else(|_| Wallet { keys: HashMap::new() })
    }

    // persitence
    pub fn save_to_file(&self, filepath: &str) -> std::io::Result<()> {
        let serialized = serde_json::to_string(&self)?;
        fs::write(filepath, serialized)?;
        Ok(())
    }

    // load wallet if exists
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

    pub fn get_key_path(&self, name: &str) -> Option<&String> {
        self.keys.get(name)
    }
}
