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
    // Generates a new key pair for a given name and encryption key
    Generate {
        // Name of the person
        #[arg(short, long)]
        name: String,

        #[arg(short, long)]
        cs_id: usize,
    },
    // Removes an existing key pair
    Remove {
        // Name of the person
        #[arg(short, long)]
        name: String,
    },
    // Signs a file with a provided persons private key
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
    },
    // Verifies the signature of a file with a provided public key
    Verify {
        // Name of the person
        #[arg(short, long)]
        name: String,

        // Path to header file with verification info
        #[arg(short = 'o', long)]
        header: String,
    },
    RemoveSignature {
        // Signature file to remove
        #[arg(short, long)]
        file: String,
    },
    ListSignatures,
    ListFiles,
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
