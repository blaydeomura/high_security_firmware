use clap::{Parser, Subcommand};
use ring::{rand, signature::Ed25519KeyPair};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Write;
use std::io::Read;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
struct Wallet {
    keys: HashMap<String, String>, // Maps a name to a path where the key is stored
}

impl Wallet {

    fn new() -> Self {
        // Try to load the wallet from a file, or create a new one if it doesn't exist
        Self::load_from_file("wallet.json").unwrap_or_else(|_| Wallet { keys: HashMap::new() })
    }

    fn save_to_file(&self, filepath: &str) -> std::io::Result<()> {
        let serialized = serde_json::to_string(&self)?;
        fs::write(filepath, serialized)?;
        Ok(())
    }

    fn load_from_file(filepath: &str) -> std::io::Result<Self> {
        let mut file = File::open(filepath)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let wallet = serde_json::from_str(&contents)?;
        Ok(wallet)
    }

    fn add_key(&mut self, name: String, path: String) {
        self.keys.insert(name, path);
    }


    fn remove_key(&mut self, name: &str) -> Option<String> {
        self.keys.remove(name)
    }

    fn get_key_path(&self, name: &str) -> Option<&String> {
        self.keys.get(name)
    }
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Generate {
        name: String,
    },
    Remove {
        name: String,
    },
    Access {
        name: String,
    },
}

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new(); // Initialize a new wallet

    match args.command {
        Commands::Generate { name } => {
            generate_key(&mut wallet, &name);
            wallet.save_to_file("wallet.json").expect("Failed to save wallet");
        },
        Commands::Remove { name } => {
            remove_key(&mut wallet, &name);
            wallet.save_to_file("wallet.json").expect("Failed to save wallet");
        },
        Commands::Access { name } => access_key(&wallet, &name),
        // Add a case for the List command if implemented
    }
}

fn key_file_path(name: &str) -> String {
    format!("keys/{}.pk8", name)
}


fn generate_key(wallet: &mut Wallet, name: &str) {
    let path = key_file_path(name);
    let path = Path::new(&path);

    if wallet.get_key_path(name).is_some() {
        println!("A key pair already exists for {}.", name);
        return;
    }

    match generate_and_save_key_pair(path) {
        Ok(_) => {
            println!("Key pair generated and saved successfully for {}.", name);
            wallet.add_key(name.to_string(), path.to_str().unwrap().to_string());
        }
        Err(e) => eprintln!("Failed to generate and save key pair: {}", e),
    }
}

fn generate_and_save_key_pair(path: &Path) -> Result<(), ring::error::Unspecified> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;
    if let Some(dir_path) = path.parent() {
        fs::create_dir_all(dir_path).expect("Failed to create directory for key storage");
    }
    let mut file = File::create(path).expect("Failed to create key file");
    file.write_all(pkcs8_bytes.as_ref()).expect("Failed to write key to file");
    Ok(())
}

fn remove_key(wallet: &mut Wallet, name: &str) {
    if let Some(path) = wallet.remove_key(name) {
        fs::remove_file(path).expect("Failed to remove key file");
        println!("Key file for {} has been removed.", name);
    } else {
        println!("No key file found for {}.", name);
    }
}

fn access_key(wallet: &Wallet, name: &str) {
    if let Some(path) = wallet.get_key_path(name) {
        match std::fs::read(path) {
            Ok(contents) => {
                let b64_contents = general_purpose::STANDARD.encode(contents);
                println!("Contents of key file for {} (Base64 encoded):\n{}", name, b64_contents);
            }
            Err(_) => println!("Error: No key file found for {}.", name),
        }
    } else {
        println!("No key file found for {}.", name);
    }
}






