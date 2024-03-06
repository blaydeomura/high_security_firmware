use std::fs;
use std::fs::File;                
use std::io::Read;                
use std::path::Path;                         
use clap::Parser;
use sha2::{Digest, Sha256, Sha384, Sha512};                       
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use rust_cli::wallet;
use rust_cli::wallet::Wallet;
use rust_cli::commands::{Args, Commands};

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new(); // Initialize or load wallet

    match args.command {
        Commands::Generate { name, encryption_key } => {
            let encryption_key_bytes = encryption_key.as_bytes();
            wallet::generate_key(&mut wallet, &name, encryption_key_bytes);
            wallet.save_to_file("wallet.json").expect("Failed to save wallet");
        },
        Commands::Remove { name } => {
            wallet::remove_key(&mut wallet, &name);
            wallet.save_to_file("wallet.json").expect("Failed to save wallet");
        },
        Commands::Access { name, encryption_key } => {
            let encryption_key_bytes = encryption_key.as_bytes();
            wallet::access_key(&wallet, &name, encryption_key_bytes);
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

// Signing and verifying
fn sign_file(wallet: &Wallet, name: &str, filename: &str, encryption_key: &[u8]) {
    if let Some(path_str) = wallet.get_key_path(name) {
        let path = Path::new(path_str);
        let encrypted_data = fs::read(path).expect("Failed to read key file");
        let decrypted_data = wallet::decrypt_data(&encrypted_data, encryption_key);

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