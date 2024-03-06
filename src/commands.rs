use clap::{Subcommand, Parser};

// command line arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

// the possible command line arguments
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generates a new key pair for a given name and encryption key
    Generate {
        /// Name of the person
        #[arg(short, long)]
        name: String,
        
        /// Encryption key to secure the key pair
        #[arg(short, long)]
        encryption_key: String,
    },
    /// Removes an existing key pair
    Remove {
        /// Name of the person
        #[arg(short, long)]
        name: String,
    },
    /// Accesses an existing key pair with the encryption key
    Access {
        /// Name of the person
        #[arg(short, long)]
        name: String,
        
        /// Encryption key to decrypt the key pair
        #[arg(short, long)]
        encryption_key: String,
    },

    HashFile {
        // Name of the file to be hashed
        #[arg(short, long)]
        filename: String,

        /// The hashing algorithm to use (e.g., blake3, sha256)
        #[arg(short, long)]
        algorithm: String,
    },

    // adding in key signing
       /// Signs a file with a given name's private key
       Sign {
        /// Name of the person
        #[arg(short, long)]
        name: String,
        
        /// File to sign
        #[arg(short, long)]
        filename: String,
    },
    
    /// Verifies a file with a given public key
    Verify {
        /// Name of the person
        #[arg(short, long)]
        name: String,
        
        /// File to verify
        #[arg(short, long)]
        filename: String,
        
        /// Signature to verify against
        #[arg(short, long)]
        signature: String,
    },
}
