// A module for parsing command line arguments using the clap library
// Commands perform various cryptographic operations

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

// Possible commands that the program accepts
#[derive(Subcommand, Debug)]
pub enum Commands {
    // Generates a new cipher suite object and saves it in wallet
    Generate {
        // Name of the person
        #[arg(short, long)]
        name: String,

        // CipherSuite ID to use
        #[arg(short, long)]
        cs_id: usize,

        // Path to wallet
        #[arg(short, long)]
        wallet_path: String,
    },
    // Removes an existing ciphersuite object from wallet
    Remove {
        // Name of the person
        #[arg(short, long)]
        name: String,

        // Path to wallet
        #[arg(short, long)]
        wallet_path: String,
    },
    // Signs a file using specified ciphersuites private key
    // Outputs a signed data file
    Sign {
        // Name of the person
        #[arg(short, long)]
        name: String,

        // File to sign
        #[arg(short, long)]
        file: String,

        // Signature output
        #[arg(short = 'o', long)]
        output: String,

        // Path to wallet
        #[arg(short, long)]
        wallet_path: String,
    },
    // Verifies a signed data file with a ciphersuites public key
    Verify {
        // Name of the person
        #[arg(short, long)]
        name: String,

        // Path to header file with verification info
        #[arg(short, long)]
        file: String,

        // Path to wallet
        #[arg(short, long)]
        wallet_path: String,
    },
    Algorithms,
}

pub fn print_ids() {
    println!();
    println!("|------------ Supported  Algorithms ------------|");
    println!("|-----------------------------------------------|");
    println!("| ID  |   Signature Algorithm |   Hash Function |");
    println!("|-----------------------------------------------|");
    println!("| 1   |   Dilithium2          |   sha256        |");
    println!("|-----------------------------------------------|");
    println!("| 2   |   Dilithium2          |   sha512        |");
    println!("|-----------------------------------------------|");
    println!("| 3   |   Falcon512           |   sha256        |");
    println!("|-----------------------------------------------|");
    println!("| 4   |   Falcon512           |   sha512        |");
    println!("|-----------------------------------------------|");
    println!("| 5   |   RSA                 |   sha256        |");
    println!("|-----------------------------------------------|");
}
