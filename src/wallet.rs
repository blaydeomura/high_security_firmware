// A module representing a wallet that stores info about individuals and where their crypto keys are stored
// Wallet contents are stored in JSON format
// Operations include loading wallet from file, saving wallet to file, and adding and removing keys

use crate::cipher_suite::{
    self, CipherSuite, Dilithium2Sha256, Dilithium2Sha512, Falcon512Sha256, Falcon512Sha512,
};

use json::JsonValue;
use std::collections::HashMap;
use std::path::Path;
use std::{fs, io};

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
            let cipher_suite = Self::deserialize_ciphersuite(json_string).unwrap();
            self.keys
                .insert(cipher_suite.get_name().clone(), cipher_suite);
        }
        Ok(())
    }

    // Parses a cs_id from a json string and creates the corresponding ciphersuite
    pub fn deserialize_ciphersuite(
        json_string: JsonValue,
    ) -> Result<Box<dyn CipherSuite>, std::io::Error> {
        let cs_id = json_string["cs_id"].as_isize();
        match cs_id {
            Some(1) => {
                let cs: Dilithium2Sha256 = serde_json::from_str(&json_string.dump())
                    .expect("Error deserializing ciphersuite");
                Ok(Box::new(cs))
            }
            Some(2) => {
                let cs: Dilithium2Sha512 = serde_json::from_str(&json_string.dump())
                    .expect("Error deserializing ciphersuite");
                Ok(Box::new(cs))
            }
            Some(3) => {
                let cs: Falcon512Sha256 = serde_json::from_str(&json_string.dump())
                    .expect("Error deserializing ciphersuite");
                Ok(Box::new(cs))
            }
            Some(4) => {
                let cs: Falcon512Sha512 = serde_json::from_str(&json_string.dump())
                    .expect("Error deserializing ciphersuite");
                Ok(Box::new(cs))
            }
            _ => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unsupported cipher suite id. Enter a value between 1-4",
                ))
            }
        }
    }

    // Creates a new ciphersuite object and serializes it
    pub fn create_ciphersuite(&mut self, name: String, cs_id: usize) -> Result<(), io::Error> {
        let lower_name = name.to_lowercase();

        match cs_id {
            1 => {
                let cs = Box::new(cipher_suite::Dilithium2Sha256::new(
                    lower_name.clone(),
                    cs_id,
                ));
                self.save_ciphersuite(&name, cs)
            }
            2 => {
                let cs = Box::new(cipher_suite::Dilithium2Sha512::new(
                    lower_name.clone(),
                    cs_id,
                ));
                self.save_ciphersuite(&name, cs)
            }
            3 => {
                let cs = Box::new(cipher_suite::Falcon512Sha256::new(
                    lower_name.clone(),
                    cs_id,
                ));
                self.save_ciphersuite(&name, cs)
            }
            4 => {
                let cs = Box::new(cipher_suite::Falcon512Sha512::new(
                    lower_name.clone(),
                    cs_id,
                ));
                self.save_ciphersuite(&name, cs)
            }
            _ => {
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Unsupported cipher suite id. Enter a value between 1-4",
                ))
            }
        }
    }

    // Serializes a ciphersuite object and saves it in keys hashmap
    pub fn save_ciphersuite(
        &mut self,
        name: &str,
        cs: Box<dyn CipherSuite>,
    ) -> std::io::Result<()> {
        let path_str = format!("wallet/{}.json", name);
        let path = Path::new(&path_str);
        let serialized = serde_json::to_string_pretty(&cs)?;
        fs::write(path, serialized)?;
        self.keys.insert(name.to_string(), cs);
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
