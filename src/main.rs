use clap::Parser;
use rust_cli::wallet::Wallet;
use rust_cli::commands::{Args, Commands};
use rust_cli::persona::Persona;
use rust_cli::file_ops::{sign, verify};

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new();

    match args.command {
        Commands::Generate { name, cs_id } => {
            let new_persona = Persona::new(name, cs_id);
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
        Commands::Access { name, encryption_key } => {
            // let encryption_key_bytes = encryption_key.as_bytes();
            // wallet::access_key(&wallet, &name, encryption_key_bytes);
        },
        Commands::Sign { name, filename } => {
            let result = sign(&name, &filename, &wallet);
            match result {
                Ok(_) => {
                    println!("Signature created successfully.");
                },
                Err(e) => println!("Error signing file: {}", e),
            }
        },
        Commands::Verify { name, filename, signature } => {
            // Directly pass the signature file path to the verify function
            let result = verify(&name, &filename, &signature, &wallet);
            match result {
                Ok(_) => println!("Verification successful."),
                Err(e) => println!("Verification failed: {}", e),
            }
        },
    }
}
