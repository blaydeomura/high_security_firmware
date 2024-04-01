use std::fs::File;
use std::io::{self, Read};
use crate::wallet::Wallet;
use std::fs;
use std::path::Path;
use std::io::ErrorKind;
use std::path::PathBuf;
use ed25519_dalek::Signer;
use oqs::sig::{self, Sig}; // Make sure to import the oqs crate correctly
use sha2::Sha256;
use crate::persona::{self, Algorithm, Persona};
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{DecodePrivateKey, DecodePublicKey}};
use rsa::traits::PaddingScheme;


use p256::ecdsa::{SigningKey, signature::Signer as _};


// This is because each sign function returns something different
enum SignatureResult {
    QuantumSafe(oqs::sig::Signature),
    Ed25519(ed25519_dalek::Signature),
    RSA(Vec<u8>),
    ECDSA(Vec<u8>),
}



pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<SignatureResult> {
    let persona = wallet.get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    let algorithm = persona::get_sig_algorithm(persona.get_cs_id())?;

    let mut file = fs::File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let hash_result_vec: Vec<u8> = persona::get_hash(persona.get_cs_id(), &buffer)?;

    let signature = match algorithm {
        persona::Algorithm::QuantumSafe(qs_algo) => {
            let sig = Sig::new(qs_algo).map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            if let Some(sk_ref) = persona.get_quantum_safe_sk_ref() {
                sig.sign(&hash_result_vec, sk_ref)
                    .map(SignatureResult::QuantumSafe)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound, "Quantum-safe secret key not found"))
            }
        },
        // Algorithm::RSA2048 => {
        //     let private_key_bytes = persona
        //         .get_rsa_sk() // Assuming this method exists and retrieves the RSA private key bytes
        //         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "RSA private key not found"))?;
        
        //     let private_key = Pkcs1PrivateKey::from_der(private_key_bytes)
        //         .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        //     let padding = PaddingScheme::new_pkcs1v15_sign(None); // Choosing PKCS#1 v1.5
        //     let rsa_signature = private_key.sign(padding, &hash_result_vec)
        //         .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        //     Ok(SignatureResult::RSA(rsa_signature))
        // },
        Algorithm::RSA2048 => {
            let private_key_bytes = persona
                .get_rsa_sk() // Ensure this retrieves the private key bytes in PKCS#8 format
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "RSA private key not found"))?;
        
            let private_key = RsaPrivateKey::from_pkcs8_der(private_key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
            let padding = PaddingScheme::new_pkcs1v15_sign(None);
            let mut rng = rand::thread_rng();
            let rsa_signature = private_key.sign(padding, &hash_result_vec, &mut rng)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
            Ok(SignatureResult::RSA(rsa_signature))
        },
        Algorithm::ECDSAP256 => {
            let secret_key_bytes = persona
                .get_ecdsa_sk() // Assuming this method exists and retrieves the ECDSA private key bytes
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ECDSA private key not found"))?;
        
            let signing_key = SigningKey::from_bytes(secret_key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
            let ecdsa_signature = signing_key.sign(&hash_result_vec);
        
            Ok(SignatureResult::ECDSA(ecdsa_signature.to_der().as_bytes().to_vec()))
        },
        persona::Algorithm::Ed25519 => {
            let secret_key_bytes = persona
            .get_ed25519_sk_bytes()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Ed25519 secret key not found"))?;
        
            // Create the secret key from bytes
            let secret_key = ed25519_dalek::SecretKey::from_bytes(secret_key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            
            // Directly create the public key from the secret key
            let public_key = ed25519_dalek::PublicKey::from(&secret_key);

            // Now create the keypair
            let keypair = ed25519_dalek::Keypair { secret: secret_key, public: public_key };

            // Signing the hash result vector
            let ed25519_signature = keypair.sign(&hash_result_vec);

            Ok(SignatureResult::Ed25519(ed25519_signature))
        }
    }?;

    Ok(signature)
}



pub fn verify(name: &str, file_path: &str, signature: SignatureResult, wallet: &Wallet) -> io::Result<bool> {
    let persona = wallet.get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    let algorithm = persona::get_sig_algorithm(persona.get_cs_id())?;

    let mut file = fs::File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let hash_result_vec: Vec<u8> = persona::get_hash(persona.get_cs_id(), &buffer)?;

    match algorithm {
        persona::Algorithm::QuantumSafe(_) => {
            // Quantum-safe verification logic...
            Err(io::Error::new(io::ErrorKind::Other, "Quantum-safe verification not implemented"))
        },
        persona::Algorithm::RSA2048 => {
            let public_key_bytes = persona
                .get_rsa_pk_bytes() // Assuming this method exists and retrieves the RSA public key bytes
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "RSA public key not found"))?;
            
            let public_key = RsaPublicKey::from_pkcs1_der(public_key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let padding = PaddingScheme::new_pkcs1v15_sign(None);
            if let SignatureResult::RSA(signature_bytes) = signature {
                public_key.verify(padding, &hash_result_vec, &signature_bytes)
                    .map(|_| true)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature type for RSA"))
            }
        },
        persona::Algorithm::ECDSAP256 => {
            let public_key_bytes = persona
                .get_ecdsa_pk_bytes() // Assuming this method exists
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ECDSA public key not found"))?;

            let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            if let SignatureResult::ECDSA(signature_bytes) = signature {
                let signature = P256Signature::from_der(&signature_bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                verifying_key.verify(&hash_result_vec, &signature)
                    .map(|_| true)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature type for ECDSA"))
            }
        },
        persona::Algorithm::Ed25519 => {
            // Ed25519 verification logic...
            if let SignatureResult::Ed25519(signature) = signature {
                let public_key_bytes = persona
                    .get_ed25519_pk_bytes()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Ed25519 public key not found"))?;
                
                let public_key = ed25519_dalek::PublicKey::from_bytes(public_key_bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

                public_key.verify(&hash_result_vec, &signature)
                    .map(|_| true)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, "Verification failed"))
            } else {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature type for Ed25519"))
            }
        }
    }
}








// removes the signature file associated with a given persona and file.
pub fn remove_signature(signature_file_name: &str) -> io::Result<()> {

    let signature_dir = "signatures/";
    let signature_file_path = Path::new(signature_dir).join(&signature_file_name);
    
    println!("Attempting to remove file at path: {:?}", signature_file_path);

    // Check if the file exists before attempting to remove it
    if signature_file_path.exists() {
        let path_to_remove = signature_file_path.clone();

        fs::remove_file(path_to_remove).map_err(|e| {
            eprintln!("Failed to remove signature file: {:?}. Error: {}", signature_file_path, e);
            io::Error::new(ErrorKind::Other, format!("Failed to remove signature file: {}", e))
        })
    } else {
        Err(io::Error::new(ErrorKind::NotFound, "Signature file does not exist"))
    }
}

// lists all signature files in the signatures directory.
pub fn list_signature_files() -> std::io::Result<()> {
    let signature_dir = "signatures";
    let paths = fs::read_dir(signature_dir)?;

    println!("Listing all signature files:");
    for path in paths {
        let path = path?.path();
        if path.is_file() {
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                println!("{}", filename);
            }
        }
    }

    Ok(())
}

// lists all the files in the "files" directory.
pub fn list_files() -> std::io::Result<()> {
    let directory_path = Path::new("files");
    
    println!("Listing files in directory: {:?}", directory_path.display());
    let entries = fs::read_dir(directory_path)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()?;

    // Attempt to create a PathBuf from the "files" directory to use for stripping
    let base_path = PathBuf::from(directory_path);

    for entry in entries {
        if entry.is_file() {
            // use the strip_prefix method to remove the "files" part from the path
            // then print the stripped path or the original path if stripping fails
            match entry.strip_prefix(&base_path) {
                Ok(stripped) => println!("{}", stripped.display()),
                Err(_) => println!("{}", entry.display()),
            }
        }
    }
    
    Ok(())
}