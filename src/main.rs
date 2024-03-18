// use clap::Parser;
// use rust_cli::wallet;
// use rust_cli::wallet::Wallet;
// use rust_cli::commands::{Args, Commands};
// use rust_cli::file_ops;
// use rust_cli::persona::Persona;
use clap::Parser;
use rust_cli::wallet::Wallet;
use rust_cli::commands::{Args, Commands};
use rust_cli::persona::Persona;
use rust_cli::file_ops::{sign, verify};
use std::fs;

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new(); // Initialize or load wallet

    match args.command {
        Commands::Generate { name, cs_id } => {
            let new_persona = Persona::new(name, cs_id);
            wallet.save_persona(new_persona).unwrap();
        },
        Commands::Remove { name } => {
            let _ = wallet.remove_persona(&name);
        },
        Commands::Access { name, encryption_key } => {
            // let encryption_key_bytes = encryption_key.as_bytes();
            // wallet::access_key(&wallet, &name, encryption_key_bytes);
        },
        Commands::HashFile { filename, algorithm } => {
            // file_ops::hash_file(&filename, &algorithm);
        },
        Commands::Sign { name, filename } => {
            let result = sign(&name, &filename, &wallet);
            match result {
                Ok(signature) => {
                    // Assuming you want to save the signature to a file
                    let signature_path = format!("{}.sig", filename);
                    fs::write(signature_path, &signature).expect("Unable to write signature");
                    println!("Signature created successfully.");
                }
                Err(e) => println!("Error signing file: {}", e),
            }
        },
        Commands::Verify { name, filename, signature } => {
            // Assuming `signature` is the path to the signature file
            let signature_data = fs::read(&signature).expect("Failed to read signature file");
            let result = verify(&name, &filename, &signature_data, &wallet);
            match result {
                Ok(_) => println!("Verification successful."),
                Err(e) => println!("Verification failed: {}", e),
            }
        }
    }
}
