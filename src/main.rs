use clap::Parser;
use rust_cli::wallet::Wallet;
use rust_cli::commands::{self, Args, Commands};
use rust_cli::persona::Persona;
use rust_cli::file_ops::{self, remove_signature, verify, list_signature_files, list_files};
use std::env;

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new();

    // Print the current directory
    let current_dir = env::current_dir().unwrap();
    println!("Current directory: {:?}", current_dir);

    let wallet_dir = current_dir.join("wallet");
    println!("Looking for wallet in: {:?}", wallet_dir);

    wallet.load_wallet(String::from("wallet")).unwrap_or_else(|_| {
        panic!("Error loading wallet");
    });

    // let args = Args::parse();
    // let mut wallet = Wallet::new();

    // wallet.load_wallet("wallet").unwrap_or_else(|_| {
    //     panic!("Error loading wallet");
    // });

    match args.command {
        Commands::Generate { name, cs_id } => {
            match Persona::new(name, cs_id) {
                Ok(new_persona) => {
                    // Now we have the Persona object, proceed with saving it
                    match wallet.save_persona(&new_persona) {
                        Ok(_) => println!("Persona created successfully"),
                        Err(e) => println!("Error creating persona: {}", e),
                    }
                },
                Err(e) => {
                    // Handle the case where Persona::new returns an error
                    println!("Error creating persona: {}", e);
                },
            }
        },
        Commands::Remove { name } => {
            let result = wallet.remove_persona(&name);
            match result {
                Ok(_) => {
                    println!("Persona removed successfully");
                }
                Err(e) => {
                    println!("Error removing persona: {}", e);
                }
            }
        },
        Commands::Sign { name, sign, header } => {
            let result = file_ops::sign(&name, &sign, &header, &wallet);
            match result {
                Ok(_) => {
                    println!("Signature created successfully.");
                },
                Err(e) => println!("Error signing file: {}", e),
            }
        },
        Commands::Verify { name, sign, header } => {
            // Directly pass the signature file path to the verify function
            let result = verify(&name, &header, &sign ,&wallet);
            match result {
                Ok(_) => println!("Verification successful."),
                Err(e) => println!("Verification failed: {}", e),
            }
        },
        Commands::RemoveSignature { file } => {
            // Directly pass the signature file path to the verify function
            let result = remove_signature(&file);
            match result {
                Ok(_) => println!("Removal successful."),
                Err(e) => println!("Removal failed: {}", e),
            }
        },
        Commands::ListSignatures => {
            if let Err(e) = list_signature_files() {
                println!("Failed to list signature files: {}", e);
            }
        },
        Commands::ListFiles => {
            if let Err(e) = list_files() {
                println!("Failed to list signature files: {}", e);
            }
        },
        Commands::Algorithms => {
            commands::print_ids();
        }
    }
}
