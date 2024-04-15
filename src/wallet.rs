// A module representing a wallet that stores info about individuals and where their crypto keys are stored
// Wallet contents are stored in JSON format
// Operations include loading wallet from file, saving wallet to file, and adding and removing keys

use super::persona::Persona;
//use serde::{Deserialize, Serialize};
use erased_serde::Deserializer;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// Wallet contains a hashmap with names of individuals and associated persona objects

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
        Wallet { keys }
    }

    // Opens all persona files in wallet folder and loads them into hashmap
    pub fn load_wallet(&mut self, dir_path: String) -> std::io::Result<()> {
        for entry in fs::read_dir(dir_path)? {
            let dir = entry?;
            let content = fs::read_to_string(dir.path())?;
            let content = content.as_bytes();
            let deserializer = &mut serde_json::Deserializer::from_slice(&content);
            let mut deserializer = Box::new(<dyn Deserializer>::erase(deserializer));
            //let persona: Persona = serde_json::from_str(&content)?;
           // let persona: Persona = erased_serde::deserialize(&mut deserializer).unwrap();
           // self.keys.insert(persona.get_name(), persona);
        }
        Ok(())
    }

    // // Creates a new persona object, stores data in hashmap, serializes data to JSON
    // pub fn save_persona(&mut self, persona: Persona) -> std::io::Result<()> {
    //     let path_str = format!("wallet/{}.json", persona.get_name());
    //     let path = Path::new(&path_str);
    //     let serialized = serde_json::to_string_pretty(&persona)?;
    //     fs::write(path, serialized)?;
    //     self.keys.insert(persona.get_name(), persona);
    //     Ok(())
    // }

    pub fn save_persona(&mut self, mut persona: Persona) -> std::io::Result<()> {
        // Convert name to lower case for case-insensitive handling
        let lower_name = persona.get_name().to_lowercase();
        persona.set_name(lower_name.clone()); // Ensure persona's name is also updated

        let path_str = format!("wallet/{}.json", lower_name);
        let path = Path::new(&path_str);
        let serialized = serde_json::to_string_pretty(&persona)?;
        fs::write(path, serialized)?;
        self.keys.insert(lower_name, persona);
        Ok(())
    }

    // // Removes data from hashmap and deletes corresponding JSON file
    // pub fn remove_persona(&mut self, name: &String) -> std::io::Result<()> {
    //     self.keys.remove(name);
    //     let path_str = format!("wallet/{}.json", name);
    //     fs::remove_file(path_str)?;
    //     Ok(())
    // }
    pub fn remove_persona(&mut self, name: &str) -> std::io::Result<()> {
        // Convert name to lower case for case-insensitive handling
        let lower_name = name.to_lowercase();

        self.keys.remove(&lower_name);
        let path_str = format!("wallet/{}.json", lower_name);
        fs::remove_file(path_str)?;
        Ok(())
    }

    // Getter for name of persona
    pub fn get_persona(&self, name: &str) -> Option<&Persona> {
        self.keys.get(&name.to_lowercase())
    }
}
