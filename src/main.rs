use clap::Parser;
use rust_cli::wallet::Wallet;
use rust_cli::commands::{self, Args, Commands};
use rust_cli::persona::Persona;
use rust_cli::file_ops::{remove_signature, sign, verify, list_signature_files, list_files};

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new();
    wallet.load_wallet(String::from("wallet")).unwrap_or_else(|_| {
        panic!("Error loading wallet");
    });

    match args.command {
        Commands::Generate { name, cs_id , non_quantum_cs_id} => {
            let new_persona = Persona::new(name, cs_id, non_quantum_cs_id);
            let result = wallet.save_persona(new_persona);
            match result {
                Ok(_) => {
                    println!("Persona created successfully");
                }
                Err(e) => {
                    println!("Error creating persona {}", e);
                }
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
        Commands::Sign { name, file } => {
            let result = sign(&name, &file, &wallet);
            match result {
                Ok(_) => {
                    println!("Signature created successfully.");
                },
                Err(e) => println!("Error signing file: {}", e),
            }
        },
        Commands::Verify { name, file, signature } => {
            // Directly pass the signature file path to the verify function
            let result = verify(&name, &file, &signature, &wallet);
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
