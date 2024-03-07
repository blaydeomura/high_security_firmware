use clap::Parser;
use rust_cli::wallet;
use rust_cli::wallet::Wallet;
use rust_cli::commands::{Args, Commands};
use rust_cli::file_ops;

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
            file_ops::hash_file(&filename, &algorithm);
        },
        Commands::Sign { name, filename } => {
            // Assuming you have the encryption key available, possibly asking the user for it
            println!("Enter the encryption key for {}: ", name);
            let mut encryption_key = String::new();
            std::io::stdin().read_line(&mut encryption_key).expect("Failed to read line");
            let encryption_key = encryption_key.trim(); // Trim newline characters

            file_ops::sign_file(&wallet, &name, &filename, encryption_key.as_bytes());
        },
        Commands::Verify { name, filename, signature } => {
            // Similarly, assuming the encryption key could be requested or derived as needed
            println!("Enter the encryption key for {}: ", name);
            let mut encryption_key = String::new();
            std::io::stdin().read_line(&mut encryption_key).expect("Failed to read line");
            let encryption_key = encryption_key.trim(); // Trim newline characters
            file_ops::verify_file(&wallet, &name, &filename, &signature, encryption_key.as_bytes());
        },
    }
}
