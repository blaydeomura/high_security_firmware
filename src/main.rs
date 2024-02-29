use clap::{Parser, Subcommand};
use ring::signature::Ed25519KeyPair;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use aes_gcm::Aes256Gcm; 
use aes_gcm::aead::generic_array::GenericArray; 
use aes_gcm::aead::Aead; 
use aes_gcm::KeyInit; 
use ::rand::rngs::OsRng;
use aes_gcm::Nonce; 
use ::rand::Rng; 


//***********Example Usages**************************************************************************/
// 1. Generate a key for a person with a specific encryption key (has to be 32 bit)
        // This will need to be more secure later
// 2. Access person's generated key with same encryption key
// 3. You can remove without key

//cargo run -- generate --name Mallory --encryption-key "ThisIsA32ByteLongEncryptionKey00"
//cargo run -- access --name Mallory --encryption-key "ThisIsA32ByteLongEncryptionKey00"
//cargo run -- remove --name Mallory 

// cargo run -- generate --name Bob --encryption-key "ThisIsA32ByteLongEncryptionKey11"
//cargo run -- access --name Bob --encryption-key "ThisIsA32ByteLongEncryptionKey11"
//cargo run -- remove --name Bob 
//*****************************************************************************************************/


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
    /// Generates a new key pair for a given name and encryption key
    Generate {
        /// Name of the person
        #[arg(short, long)]
        name: String,
        
        /// Encryption key to secure the key pair
        #[arg(short, long)]
        encryption_key: String,
    },
    /// Removes an existing key pair
    Remove {
        /// Name of the person
        #[arg(short, long)]
        name: String,
    },
    /// Accesses an existing key pair with the encryption key
    Access {
        /// Name of the person
        #[arg(short, long)]
        name: String,
        
        /// Encryption key to decrypt the key pair
        #[arg(short, long)]
        encryption_key: String,
    },
}


fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new(); // Initialize or load wallet

    match args.command {
        Commands::Generate { name, encryption_key } => {
            let encryption_key_bytes = encryption_key.as_bytes();
            generate_key(&mut wallet, &name, encryption_key_bytes);
            wallet.save_to_file("wallet.json").expect("Failed to save wallet");
        },
        Commands::Remove { name } => {
            remove_key(&mut wallet, &name);
            wallet.save_to_file("wallet.json").expect("Failed to save wallet");
        },
        Commands::Access { name, encryption_key } => {
            let encryption_key_bytes = encryption_key.as_bytes();
            access_key(&wallet, &name, encryption_key_bytes);
        },
    }
}


fn key_file_path(name: &str) -> String {
    format!("keys/{}.pk8", name)
}


fn generate_key(wallet: &mut Wallet, name: &str, encryption_key: &[u8]) {
    let path_str = key_file_path(name);
    let path = Path::new(&path_str);

    if wallet.get_key_path(name).is_some() {
        println!("A key pair already exists for {}.", name);
        return;
    }

    match generate_and_save_key_pair(path, encryption_key) {
        Ok(_) => {
            println!("Key pair generated and saved successfully for {}.", name);
            wallet.add_key(name.to_string(), path_str);
            wallet.save_to_file("wallet.json").expect("Failed to save wallet.");
        },
        Err(e) => eprintln!("Failed to generate and save key pair for {}: {}", name, e),
    }
}


fn generate_and_save_key_pair(path: &Path, encryption_key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes_result = Ed25519KeyPair::generate_pkcs8(&rng);

    // Manually handle the error
    let pkcs8_bytes = pkcs8_bytes_result.map_err(|e| format!("Failed to generate key pair: {:?}", e))?;

    // Proceed with encryption and saving the key
    let encrypted_data = encrypt_data(&pkcs8_bytes.as_ref().to_vec(), encryption_key);
    
    if let Some(dir_path) = path.parent() {
        std::fs::create_dir_all(dir_path)?;
    }
    std::fs::write(path, &encrypted_data)?;

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

fn access_key(wallet: &Wallet, name: &str, encryption_key: &[u8]) {
    if let Some(path_str) = wallet.get_key_path(name) {
        let path = Path::new(path_str);
        match fs::read(path) {
            Ok(encrypted_data) => {
                let decrypted_data = decrypt_data(&encrypted_data, encryption_key);
                // let b64_contents = base64::encode(&decrypted_data);
                let b64_contents = general_purpose::STANDARD.encode(&decrypted_data);

                println!("Decrypted key for {} (Base64 encoded):\n{}", name, b64_contents);
            },
            Err(_) => println!("Error: No key file found for {}.", name),
        }
    } else {
        println!("No key file found for {}.", name);
    }
}


fn encrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    
    // Create the nonce and store it in a variable to extend its lifetime
    let nonce_array = OsRng.gen::<[u8; 12]>(); // Generate a random nonce
    let nonce = Nonce::from_slice(&nonce_array); // Convert the array into a Nonce type
    
    let encrypted_data = cipher.encrypt(nonce, data.as_ref())
        .expect("encryption failure");
    
    // Prepend nonce to encrypted data
    [nonce.as_slice(), encrypted_data.as_slice()].concat()
}


fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let (nonce, ciphertext) = encrypted_data.split_at(12);
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
        .expect("decryption failure")
}

