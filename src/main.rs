use clap::Parser;
use rust_cli::wallet;
use rust_cli::wallet::Wallet;
use rust_cli::commands::{Args, Commands};
use rust_cli::file_ops;
use rust_cli::persona::Persona;

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
            // Assuming you have the encryption key available, possibly asking the user for it
            // println!("Enter the encryption key for {}: ", name);
            // let mut encryption_key = String::new();
            // std::io::stdin().read_line(&mut encryption_key).expect("Failed to read line");
            // let encryption_key = encryption_key.trim(); // Trim newline characters

            // file_ops::sign_file(&wallet, &name, &filename, encryption_key.as_bytes());
        },
        Commands::Verify { name, filename, signature } => {
            // file_ops::verify_file(&wallet, &name, &filename, &signature);
        }
    }
}
