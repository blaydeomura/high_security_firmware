use oqs::sig::{self, Sig, Signature};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use crate::wallet::Wallet;
use crate::persona::get_sig_algorithm;
use std::fs;
use std::path::Path;
use std::io::Write;
use hex;

pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<Signature> {
    // Get persona from wallet
    let persona = wallet.get_persona(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // Choose correct algorithm based on persona and cryptographic suite ID they used
    let algorithm = get_sig_algorithm(persona.get_cs_id());
    let sig_algo = Sig::new(algorithm)
        .expect("Failed to create Sig object");

    // Get the file and hash it using SHA-256
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    let hash_result = hasher.finalize();

    // Sign the hash
    let signature = sig_algo.sign(hash_result.as_slice(), persona.get_sk())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

    // Generate a unique file name based on persona name and a hash of the original file name
    let file_name_hash = {
        let mut hasher = Sha256::new();
        hasher.update(Path::new(file_path).file_name().unwrap().to_string_lossy().as_bytes());
        hasher.finalize()
    };
    let original_file_name = Path::new(file_path).file_name().unwrap().to_string_lossy();
    let signature_file_name = format!("{}_{}.sig", name, original_file_name);
    
    // Write the signature to a file in the "signatures" directory
    let signature_dir = "signatures";
    if !Path::new(signature_dir).exists() {
        fs::create_dir(signature_dir)?;
    }
    let signature_file_path = Path::new(signature_dir).join(signature_file_name);
    let mut signature_file = File::create(&signature_file_path)?;
    // Serialize the signature into bytes using serde
    let serialized_signature = serde_json::to_vec(&signature)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Serialization failed: {}", e)))?;
    signature_file.write_all(&serialized_signature)?;

    Ok(signature)
}




pub fn verify(name: &str, file_path: &str, signature_bytes: &[u8], wallet: &Wallet) -> io::Result<()> {
    // get correct person from wallet
    let persona = wallet.get_persona(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // choose correc algo according to persona
    let algorithm = get_sig_algorithm(persona.get_cs_id());
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // hash the same file and repeat process
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    let hash_result = hasher.finalize();

    // Correctly convert signature_bytes into a SignatureRef
    let signature_ref = sig_algo.signature_from_bytes(signature_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;


    sig_algo.verify(hash_result.as_slice(), signature_ref, persona.get_pk())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Verification failed: {}", e)))?;

    Ok(())
}









// use std::fs;
// use std::fs::File;                
// use std::io::Read;                
// use std::path::Path;                         
// use sha2::{Digest, Sha256, Sha384, Sha512}; 
// use base64::{Engine as _, engine::general_purpose::STANDARD};
// use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
// use super::wallet;
// use super::wallet::Wallet;

// pub fn hash_file(filename: &str, algorithm: &str) {
//     let path = Path::new(filename);
//     let mut file = match File::open(&path) {
//         Err(why) => panic!("Couldn't open {}: {}", path.display(), why),
//         Ok(file) => file,
//     };

//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer).expect("Couldn't read file");

//     match algorithm.to_lowercase().as_str() {
//         "blake3" => {
//             let hash = blake3::hash(&buffer);
//             println!("BLAKE3 Hash: {:?}", hash);
//         },
//         "sha256" => {
//             let hash = Sha256::digest(&buffer);
//             println!("SHA-256 Hash: {:x}", hash);
//         },
//         "sha384" => {
//             let hash = Sha384::digest(&buffer);
//             println!("SHA-384 Hash: {:x}", hash);
//         },
//         "sha512" => {
//             let hash = Sha512::digest(&buffer);
//             println!("SHA-512 Hash: {:x}", hash);
//         },
//         // Add other algorithms here...
//         _ => println!("Unsupported algorithm. Please specify a valid algorithm."),
//     }
// }

// pub fn sign_file(wallet: &Wallet, name: &str, filename: &str, encryption_key: &[u8]) -> String {
//     if let Some(path_str) = wallet.get_key_path(name) {
//         let path = Path::new(path_str);
//         let encrypted_data = fs::read(path).expect("Failed to read key file");
//         let decrypted_data = wallet::decrypt_data(&encrypted_data, encryption_key);

//         let key_pair = Ed25519KeyPair::from_pkcs8(&decrypted_data).expect("Invalid PKCS8");
//         let file_data = fs::read(filename).expect("Failed to read file to sign");
        
//         let signature = key_pair.sign(&file_data);

//         // Output the signature in a usable format, e.g., hex or base64
//         println!("Signature (Base64 encoded): {}", STANDARD.encode(signature.as_ref()));
//         // Returning the signature as a String (for example, encoded in Base64)
//         STANDARD.encode(signature.as_ref())
        
//     } else {
//         println!("No key file found for {}.", name);
//         String::new() // Return an empty string if no key file is found
//     }
// }

// pub fn verify_file(_wallet: &Wallet, name: &str, filename: &str, signature: &str) {
//     // Load the public key
//     let public_key_path = format!("keys/{}.pub.pk8", name);
//     let public_key_data = fs::read(public_key_path).expect("Failed to read public key file");
    
//     let file_data = fs::read(filename).expect("Failed to read file to verify");
//     let signature_bytes = STANDARD.decode(signature)
//     .expect("Failed to decode signature");

//     // Use the loaded public key for verification
//     let public_key = UnparsedPublicKey::new(&ED25519, public_key_data.as_slice()); // Use as_slice() here
//     match public_key.verify(file_data.as_slice(), &signature_bytes) { // Ensure file_data is treated as a slice
//         Ok(_) => println!("Verification successful."),
//         Err(_) => println!("Verification failed."),
//     }
// }