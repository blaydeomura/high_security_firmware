use clap::{Parser, Subcommand};
use ring::rand;
// use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::signature::Ed25519KeyPair;
use std::fs::{self, File};
// use std::io::{self, Read, Write};
use std::io::Write;

use std::path::Path;
// use base64;
// use base64::{Engine as _, engine::{self, general_purpose}, alphabet};
use base64::{Engine as _, engine::general_purpose};


//*************To run************** */
// Generate Key: cargo run -- generate --name "<insert name>"
// Remove Key: cargo run -- remove --name "<insert name>"
// Access Key: cargo run -- access --name "<insert name>"


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates a new key pair
    Generate {
        /// Name of the person
        #[arg(short, long)]
        name: String,
    },
    /// Removes an existing key file
    Remove {
        /// Name of the person
        #[arg(short, long)]
        name: String,
    },
    /// Accesses (displays) an existing key file
    Access {
        /// Name of the person
        #[arg(short, long)]
        name: String,
    },
}

// Main function 
fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Generate { name } => generate_key(&name),
        Commands::Remove { name } => remove_key(&name),
        Commands::Access { name } => access_key(&name),
    }
}

fn key_file_path(name: &str) -> String {
    format!("keys/{}.pk8", name)
}

fn generate_key(name: &str) {
    let path = key_file_path(name);
    let path = Path::new(&path);

    if path.exists() {
        println!("A key pair already exists for {}.", name);
        return;
    }

    match generate_and_save_key_pair(path) {
        Ok(_) => println!("Key pair generated and saved successfully for {}.", name),
        Err(e) => eprintln!("Failed to generate and save key pair: {}", e),
    }
}

fn remove_key(name: &str) {
    let path = key_file_path(name);

    if Path::new(&path).exists() {
        fs::remove_file(path).expect("Failed to remove key file");
        println!("Key file for {} has been removed.", name);
    } else {
        println!("No key file found for {}.", name);
    }
}


fn access_key(name: &str) {
    let path = key_file_path(name);

    match std::fs::read(&path) {
        Ok(contents) => {
            // let b64_contents = base64::encode(contents);
            let b64_contents = general_purpose::STANDARD.encode(contents);

            println!("Contents of key file for {} (Base64 encoded):\n{}", name, b64_contents);
        },
        Err(_) => println!("No key file found for {}.", name),
    }
}



fn generate_and_save_key_pair(path: &Path) -> Result<(), ring::error::Unspecified> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;

    if let Some(dir_path) = path.parent() {
        fs::create_dir_all(dir_path).expect("Failed to create directory for key storage");
    }

    let mut file = File::create(path).expect("Failed to create key file");
    file.write_all(pkcs8_bytes.as_ref()).expect("Failed to write key to file");

    Ok(())
}