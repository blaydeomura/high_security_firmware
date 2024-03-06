use std::io::Read;                
use std::fs::File;                
use std::path::Path;                         
use sha2::{Digest, Sha256, Sha384, Sha512};                       
use base64::{Engine as _, engine::general_purpose, engine::general_purpose::STANDARD};
use aes_gcm::Aes256Gcm; 
use aes_gcm::aead::generic_array::GenericArray; 
use aes_gcm::aead::Aead; 
use aes_gcm::KeyInit; 
use ::rand::rngs::OsRng;
use aes_gcm::Nonce; 
use ::rand::Rng; 
use clap::Parser;
use std::fs;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use std::path::PathBuf;
use std::{error::Error, fmt};
use ring::error::KeyRejected;

use rust_cli::wallet::Wallet;
use rust_cli::commands::{Args, Commands};

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
        Commands::HashFile { filename, algorithm } => {
            hash_file(&filename, &algorithm);
        },

        //adding in signing and verify
        Commands::Sign { name, filename } => {
            // Assuming you have the encryption key available, possibly asking the user for it
            println!("Enter the encryption key for {}: ", name);
            let mut encryption_key = String::new();
            std::io::stdin().read_line(&mut encryption_key).expect("Failed to read line");
            let encryption_key = encryption_key.trim(); // Trim newline characters

            sign_file(&wallet, &name, &filename, encryption_key.as_bytes());
        },
        Commands::Verify { name, filename, signature } => {
            // Similarly, assuming the encryption key could be requested or derived as needed
            println!("Enter the encryption key for {}: ", name);
            let mut encryption_key = String::new();
            std::io::stdin().read_line(&mut encryption_key).expect("Failed to read line");
            let encryption_key = encryption_key.trim(); // Trim newline characters

            verify_file(&wallet, &name, &filename, &signature, encryption_key.as_bytes());
        },
    }
}


fn hash_file(filename: &str, algorithm: &str) {
    let path = Path::new(filename);
    let mut file = match File::open(&path) {
        Err(why) => panic!("Couldn't open {}: {}", path.display(), why),
        Ok(file) => file,
    };

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Couldn't read file");

    match algorithm.to_lowercase().as_str() {
        "blake3" => {
            let hash = blake3::hash(&buffer);
            println!("BLAKE3 Hash: {:?}", hash);
        },
        "sha256" => {
            let hash = Sha256::digest(&buffer);
            println!("SHA-256 Hash: {:x}", hash);
        },
        "sha384" => {
            let hash = Sha384::digest(&buffer);
            println!("SHA-384 Hash: {:x}", hash);
        },
        "sha512" => {
            let hash = Sha512::digest(&buffer);
            println!("SHA-512 Hash: {:x}", hash);
        },
        // Add other algorithms here...
        _ => println!("Unsupported algorithm. Please specify a valid algorithm."),
    }
}

// Format our path
fn key_file_path(name: &str) -> String {
    format!("keys/{}.pk8", name)
}

// generate key pair for a person
// name and encryption key and saves to file
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

fn generate_and_save_key_pair(path: &Path, encryption_key: &[u8]) -> Result<(), MyError> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(MyError::from)?;

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(MyError::from)?;

    // Encrypt and save the private key
    let encrypted_data = encrypt_data(pkcs8_bytes.as_ref(), encryption_key);
    fs::write(path, &encrypted_data)
        .map_err(|_e| MyError::Unspecified(ring::error::Unspecified {}))?; // You need a way to convert io::Error to MyError

    // Save the public key
    let public_key_bytes = key_pair.public_key().as_ref();
    let public_key_path = path.with_extension("pub.pk8");
    fs::write(public_key_path, public_key_bytes)
        .map_err(|_e| MyError::Unspecified(ring::error::Unspecified {}))?; // Same here

    Ok(())
}


fn remove_key(wallet: &mut Wallet, name: &str) {
    if let Some(path_str) = wallet.remove_key(name) {
        // Convert the private key path from String to PathBuf
        let private_key_path = PathBuf::from(path_str);
        
        // Attempt to remove the private key file
        if fs::remove_file(&private_key_path).is_ok() {
            println!("Private key file for {} has been removed.", name);
        } else {
            eprintln!("Failed to remove private key file for {}.", name);
        }

        // Construct the path for the public key file by changing the extension
        let public_key_path = private_key_path.with_extension("pub.pk8");
        
        // Attempt to remove the public key file
        if fs::remove_file(&public_key_path).is_ok() {
            println!("Public key file for {} has been removed.", name);
        } else {
            eprintln!("Failed to remove public key file for {}.", name);
        }
    } else {
        println!("No key file found for {}.", name);
    }
}

// access key from persitent wallet
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

// Encrypts data with AES-GCM library with a provided key
// NEEDS UPDATE TO MORE SECURE
fn encrypt_data(data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));

    // Create the nonce and store it in a variable to extend its lifetime
    let nonce_array = OsRng.gen::<[u8; 12]>();  // Generate a random nonce
    let nonce = Nonce::from_slice(&nonce_array); // Convert the array into a Nonce type
    
    let encrypted_data = cipher.encrypt(nonce, data.as_ref())
        .expect("encryption failure");
    
    // Prepend nonce to encrypted data
    [nonce.as_slice(), encrypted_data.as_slice()].concat()
}

// Decryption
fn decrypt_data(encrypted_data: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    let (nonce, ciphertext) = encrypted_data.split_at(12);
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext.as_ref())
        .expect("decryption failure")
}


// Signing and verifying
fn sign_file(wallet: &Wallet, name: &str, filename: &str, encryption_key: &[u8]) {
    if let Some(path_str) = wallet.get_key_path(name) {
        let path = Path::new(path_str);
        let encrypted_data = fs::read(path).expect("Failed to read key file");
        let decrypted_data = decrypt_data(&encrypted_data, encryption_key);

        let key_pair = Ed25519KeyPair::from_pkcs8(&decrypted_data).expect("Invalid PKCS8");
        let file_data = fs::read(filename).expect("Failed to read file to sign");
        
        let signature = key_pair.sign(&file_data);

        // Output the signature in a usable format, e.g., hex or base64
        // println!("Signature (Base64 encoded): {}", base64::encode(signature.as_ref()));
        println!("Signature (Base64 encoded): {}", STANDARD.encode(signature.as_ref()));
    } else {
        println!("No key file found for {}.", name);
    }
}

fn verify_file(_wallet: &Wallet, name: &str, filename: &str, signature: &str, _encryption_key: &[u8]) {
    // Load the public key
    let public_key_path = format!("keys/{}.pub.pk8", name);
    let public_key_data = fs::read(public_key_path).expect("Failed to read public key file");
    
    let file_data = fs::read(filename).expect("Failed to read file to verify");
    // let signature_bytes = base64::decode(signature).expect("Failed to decode signature");
    let signature_bytes = STANDARD.decode(signature)
    .expect("Failed to decode signature");

    // Use the loaded public key for verification
    let public_key = UnparsedPublicKey::new(&ED25519, public_key_data.as_slice()); // Use as_slice() here
    match public_key.verify(file_data.as_slice(), &signature_bytes) { // Ensure file_data is treated as a slice
        Ok(_) => println!("Verification successful."),
        Err(_) => println!("Verification failed."),
    }
}



// Error handling below
#[derive(Debug)]
enum MyError {
    KeyRejected(KeyRejected),
    Unspecified(ring::error::Unspecified), // Add this line
    // expand on cases later
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MyError::KeyRejected(e) => write!(f, "Key rejected: {:?}", e),
            MyError::Unspecified(_) => write!(f, "An unspecified error occurred"),
            // Input other cases here
        }
    }
}

impl Error for MyError {}

impl From<KeyRejected> for MyError {
    fn from(err: KeyRejected) -> MyError {
        MyError::KeyRejected(err)
    }
}

impl From<ring::error::Unspecified> for MyError {
    fn from(err: ring::error::Unspecified) -> MyError {
        MyError::Unspecified(err)
    }
}





