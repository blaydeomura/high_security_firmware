// A module for parsing command line arguments using the clap library
// Commands perform various cryptographic operations

use clap::{Subcommand, Parser};

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
        cs_id: usize

        // // Encryption key to secure the key pair
        // #[arg(short, long)]
        // encryption_key: String,
    },
    // Removes an existing key pair
    Remove {
        // Name of the person
        #[arg(short, long)]
        name: String,
    },
    // Accesses an existing key pair with the encryption key
    Access {
        // Name of the person
        #[arg(short, long)]
        name: String,
        
        // Encryption key to decrypt the key pair
        #[arg(short, long)]
        encryption_key: String,
    },
    // Hashes a provided file with the specfified algorithm
    HashFile {
        // Name of the file to be hashed
        #[arg(short, long)]
        filename: String,

        /// The hashing algorithm to use (e.g., blake3, sha256)
        #[arg(short, long)]
        algorithm: String,
    },
    // Signs a file with a provided persons private key
    Sign {
    // Name of the person
    #[arg(short, long)]
    name: String,
    
    // File to sign
    #[arg(short, long)]
    filename: String,
    },
    // Verifies the signature of a file with a provided public key
    Verify {
        // Name of the person
        #[arg(short, long)]
        name: String,
        
        // File to verify
        #[arg(short, long)]
        filename: String,
        
        // Signature to verify against
        #[arg(short, long)]
        signature: String,
    },
}
