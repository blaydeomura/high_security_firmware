use clap::Parser;
use rust_cli::cipher_suite;
use rust_cli::commands::{self, Args, Commands};
use rust_cli::wallet::Wallet;

fn main() {
    let args = Args::parse();
    let mut wallet = Wallet::new();

    match args.command {
        Commands::Generate {
            name,
            cs_id,
            wallet_path,
        } => {
            wallet
                .load_wallet(&wallet_path)
                .expect("Unable to load wallet");
            let cs =
                cipher_suite::create_ciphersuite(name, cs_id).expect("Error creating ciphersuite");
            let result = wallet.save_ciphersuite(cs, &wallet_path);
            if let Err(e) = result {
                println!("Error creating ciphersuite: {}", e);
            } else {
                println!("Ciphersuite created successfully");
            }
        }
        Commands::Remove { name, wallet_path } => {
            wallet
                .load_wallet(&wallet_path)
                .expect("Unable to load wallet");
            let result = wallet.remove_ciphersuite(&name, &wallet_path);
            if let Err(e) = result {
                println!("Error removing ciphersuite: {}", e);
            } else {
                println!("Ciphersuite removed successfully");
            }
        }
        Commands::Sign {
            name,
            file,
            output,
            wallet_path,
        } => {
            wallet
                .load_wallet(&wallet_path)
                .expect("Unable to load wallet");
            let cipher_suite = wallet.get_ciphersuite(&name).unwrap().to_box();
            let result = cipher_suite.sign(&file, &output);
            if let Err(e) = result {
                println!("Signing error: {}", e);
            } else {
                println!("File signed successfully");
            }
        }
        Commands::Verify {
            name,
            file,
            wallet_path,
        } => {
            wallet
                .load_wallet(&wallet_path)
                .expect("Unable to load wallet");
            let cipher_suite = wallet.get_ciphersuite(&name).unwrap().to_box();
            let result = cipher_suite.verify(&file);
            if let Err(e) = result {
                println!("Verification error: {}", e);
            } else {
                println!("File verified successfully");
            }
        }
        Commands::PeerVerify { pk, file } => {
            let signed_data = cipher_suite::read_and_deserialize(&file)
                .expect("Unable to deserialize signed data");
            
        }
        Commands::Algorithms => {
            commands::print_ids();
        }
    }
}
