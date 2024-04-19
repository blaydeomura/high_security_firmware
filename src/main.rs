use clap::Parser;
use rust_cli::commands::{self, Args, Commands};
use rust_cli::wallet::Wallet;
use rust_cli::{cipher_suite, file_ops};

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new();
    wallet
        .load_wallet(String::from("wallet"))
        .unwrap_or_else(|_| {
            panic!("Error loading wallet");
        });

    match args.command {
        Commands::Generate { name, cs_id } => {
            let cs =
                cipher_suite::create_ciphersuite(name, cs_id).expect("Error creating ciphersuite");
            let result = wallet.save_ciphersuite(cs);
            if let Err(e) = result {
                println!("Error creating ciphersuite: {}", e);
            } else {
                println!("Ciphersuite created successfully");
            }
        }
        Commands::Remove { name } => {
            let result = wallet.remove_ciphersuite(&name);
            if let Err(e) = result {
                println!("Error removing ciphersuite: {}", e);
            } else {
                println!("Ciphersuite removed successfully");
            }
        }
        Commands::Sign { name, file, output } => {
            let cipher_suite = wallet.get_ciphersuite(&name).unwrap();
            let result = cipher_suite.sign(&file, &output);
            if let Err(e) = result {
                println!("Signing error: {}", e);
            } else {
                println!("File signed successfully");
            }
        }
        Commands::Verify { name, header } => {
            let cipher_suite = wallet.get_ciphersuite(&name).unwrap();
            let result = cipher_suite.verify(&header);
            if let Err(e) = result {
                println!("Verification error: {}", e);
            } else {
                println!("File verified successfully");
            }
        }
        Commands::RemoveSignature { file } => {
            // Directly pass the signature file path to the verify function
            let result = file_ops::remove_signature(&file);
            match result {
                Ok(_) => println!("Removal successful."),
                Err(e) => println!("Removal failed: {}", e),
            }
        }
        Commands::ListSignatures => {
            if let Err(e) = file_ops::list_signature_files() {
                println!("Failed to list signature files: {}", e);
            }
        }
        Commands::ListFiles => {
            if let Err(e) = file_ops::list_files() {
                println!("Failed to list signature files: {}", e);
            }
        }
        Commands::Algorithms => {
            commands::print_ids();
        }
    }
}
