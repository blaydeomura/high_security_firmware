// A module representing a wallet that stores info about individuals and where their crypto keys are stored
// Wallet contents are stored in JSON format
// Operations include loading wallet from file, saving wallet to file, and adding and removing keys

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
        let mut keys = HashMap::new();
        // Initialize personas and add them to the wallet
        let persona1 = Persona::new("test_persona".to_string(), 1);
        keys.insert(persona1.get_name(), persona1);

        // Add more personas as needed

        Wallet { keys }
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
}

