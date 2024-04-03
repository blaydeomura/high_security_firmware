use oqs::sig::{PublicKey, Sig, Signature};
use serde::{Serialize, Deserialize};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use crate::wallet::Wallet;
use crate::persona::{get_hash, get_sig_algorithm, Persona};
use std::fs;
use std::path::Path;
use std::io::ErrorKind;
use std::path::PathBuf;
use crate::persona::Algorithm;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey, Verifier, SignatureError};
use p256::{PublicKey as P256PublicKey, ecdsa::{VerifyingKey as P256VerifyingKey, signature::Verifier as P256Verifier, Signature as P256Signature}};
use std::convert::TryFrom;
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, pkcs1v15::Pkcs1v15Sign};
// use rsa::pkcs1::FromRsaPublicKey;
use rsa::traits::PaddingScheme;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{SigningKey, VerifyingKey as Pkcs1VerifyingKey};
// use rsa::pkcs1v15;

use sha2::{Sha256, Sha512, Digest};
use rsa::traits::SignatureScheme;



// Done || 1) Fix the impl header to work
    // - Need to change if it is get_pk for qunatum or for non quantum
// 2) Fix construct header
// 3) Implement sign
// 4) Implement verify




// This is because each sign function returns something different
enum SignatureResult {
    QuantumSafe(oqs::sig::Signature),
    Ed25519(ed25519_dalek::Signature),
    RSA(Vec<u8>),
    ECDSA(Vec<u8>),
}

// A struct to store information about a file and its signature
#[derive(Serialize, Deserialize, Debug)]
struct Header {
    file_type: usize,
    cs_id: usize,
    length: usize,
    file_hash: Vec<u8>,
    signer: Vec<u8>, 
    signature: Vec<u8>,
    contents: Vec<u8>,
}


impl Header {
    // Checks if public keys match
    fn verify_sender(&self, persona: &Persona) -> bool {
        let pk_bytes = match self.cs_id {
            1 | 2 => persona.get_quantum_safe_pk()
                            .map(|pk| pk.as_ref().to_vec()), // Convert to Vec<u8>
            3 | 4 => persona.get_quantum_safe_pk()
                            .map(|pk| pk.as_ref().to_vec()), // Convert to Vec<u8>
            5 => persona.get_ed25519_pk_bytes()
                    .map(|bytes| bytes.to_vec()), // Convert &[u8] to Vec<u8> to match types
            6 => persona.get_rsa_pk_bytes()
                    .map(|bytes| bytes.to_vec()), 
            7 => persona.get_ecdsa_pk_bytes()
                    .map(|bytes| bytes.to_vec()), 
            _ => None,
        };

        match pk_bytes {
            Some(pk) => self.signer == pk,
            None => false, // Public key not found or cs_id does not match, verification failed
        }
    }


    // Checks if length field matches actaul length of message
    fn verify_message_len(&self, length: usize) {
        assert_eq!(self.length, length, "Verification failed: invalid message length");
    }

    // Checks if hash of file contents matches expected hash
    fn verify_hash(&self, contents: &Vec<u8>) {
        let generated_hash = get_hash(self.cs_id, contents).unwrap();
        assert!(do_vecs_match(&generated_hash, &self.file_hash), "Verification failed: invalid file contents");
    }

    // Checks if signature is valid
    // fn verify_signature(&self, sig_algo: Sig, persona: &Persona) {
    //     assert!(sig_algo.verify(&self.file_hash, &self.signature, persona.get_pk()).is_ok(), "Verification failed: invalid signature");
    // }
    fn verify_signature(&self, persona: &Persona) -> Result<(), String> {
        let algorithm_result = get_sig_algorithm(self.cs_id);

        match algorithm_result {
            Ok(Algorithm::QuantumSafe(algo)) => {
                if let Some(pk) = persona.get_quantum_safe_pk() {
                    let sig = oqs::sig::Sig::new(algo).map_err(|e| e.to_string())?;

                    // Convert the Vec<u8> signature into a SignatureRef using signature_from_bytes
                    let signature_ref = sig.signature_from_bytes(&self.signature)
                        .ok_or("Failed to convert signature bytes into SignatureRef")?;

                    // Use the SignatureRef in the verify call
                    sig.verify(&self.file_hash, signature_ref, pk).map_err(|e| e.to_string())
                } else {
                    Err("QuantumSafe public key not found".into())
                }
            },
            Ok(Algorithm::Ed25519) => {
                if let Some(pk_bytes) = persona.get_ed25519_pk_bytes() {
                    if pk_bytes.len() == 32 {
                        let bytes: &[u8; 32] = pk_bytes.try_into().expect("Slice with incorrect length");
                        let verifying_key = VerifyingKey::from_bytes(bytes)
                            .map_err(|e| format!("Failed to create Ed25519 VerifyingKey: {}", e))?;
            
                        if self.signature.len() == 64 {
                            let signature_bytes: &[u8; 64] = self.signature.as_slice().try_into()
                                .expect("Signature slice with incorrect length");
            
                            let signature = Ed25519Signature::try_from(&signature_bytes[..])
                                .map_err(|e| format!("Failed to create Ed25519 Signature: {}", e.to_string()))?;
            
                            verifying_key.verify(&self.file_hash, &signature)
                                .map_err(|_| "Verification failed: invalid Ed25519 signature".to_string())
                        } else {
                            Err("Ed25519 signature must be exactly 64 bytes long".into())
                        }
                    } else {
                        Err("Ed25519 public key must be exactly 32 bytes".into())
                    }
                } else {
                    Err("Ed25519 public key not found".into())
                }
            },
            Ok(Algorithm::RSA2048) => {
                todo!()
                // if let Some(pk_bytes) = persona.get_rsa_pk_bytes() {
                //     // Decode the RSA public key from its PKCS#1 DER format
                //     let rsa_pub_key = RsaPublicKey::from_pkcs1_der(pk_bytes)
                //         .map_err(|e| format!("Failed to parse RSA public key: {}", e))?;
                    
                //     let hashed_data = get_hash(persona.get_cs_id(), &self.contents)
                //         .map_err(|e| format!("Failed to hash data: {}", e))?;
            
                //     // Assuming self.signature is a Vec<u8> containing the raw signature bytes
                //     let signature = &self.signature[..]; // Convert Vec<u8> to &[u8] for verification
            
                //     // Perform the signature verification using the RSA public key
                //     match rsa_pub_key.verify(hashed_data, signature) {
                //         Ok(_) => Ok(()),
                //         Err(_) => Err("Verification failed: invalid RSA signature".into()),
                //     }
                // } else {
                //     Err("RSA public key not found".into())
                // }
            },
            Ok(Algorithm::ECDSAP256) => {
                if let Some(pk_bytes) = persona.get_ecdsa_pk_bytes() {
                    let verifying_key = P256VerifyingKey::from_sec1_bytes(pk_bytes)
                        .map_err(|e| format!("Failed to create ECDSA P-256 VerifyingKey: {}", e))?;
                    
                    let signature = P256Signature::try_from(self.signature.as_slice())
                        .map_err(|_| "Failed to parse ECDSA P-256 signature".to_string())?;
                    
                    verifying_key.verify(&self.file_hash, &signature)
                        .map_err(|_| "Verification failed: invalid ECDSA P-256 signature".to_string())
                } else {
                    Err("ECDSA P-256 public key not found".into())
                }
            }            
            Err(e) => Err(e.to_string()),
            _ => Err("Unsupported or unknown algorithm".into()),
        }
    }
}

// Helper function to check if two vectors are equal
fn do_vecs_match<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
    let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
    matching == a.len() && matching == b.len()
}

// Constructs a header with the given information
fn construct_header(persona: &Persona, file_hash: Vec<u8>, signature: Signature, length: usize, contents: Vec<u8>) -> Header {
    Header {
        file_type: 1,
        cs_id: persona.get_cs_id(),
        length,
        file_hash,
        signer: persona.get_pk().clone(),
        signature,
        contents
    }
}


pub fn sign(name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
    // Retrieve the correct persona
    let persona = wallet.get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // Get the algorithm corresponding to the persona
    let algorithm = get_sig_algorithm(persona.get_cs_id())?;

    // Read the file contents
    let mut in_file = File::open(input)?;
    let mut contents = Vec::new();
    in_file.read_to_end(&mut contents)?;
    let file_hash: Vec<u8> = get_hash(persona.get_cs_id(), &contents)?;

    // Perform signing based on the algorithm
    let signature = match algorithm {
        Algorithm::QuantumSafe(algo) => {
            let sig = OqsSig::new(algo).expect("Failed to create Sig object");
            let secret_key = persona.get_quantum_safe_sk().expect("Secret key not found");
            let signature = sig.sign(&file_hash, secret_key).expect("Signing failed");
            SignatureResult::QuantumSafe(signature)
        },
        Algorithm::Ed25519 => {
            let secret_key_bytes = persona.get_ed25519_sk_bytes().expect("Secret key bytes not found");
            let keypair = Ed25519Keypair::from_bytes(secret_key_bytes).expect("Failed to create keypair");
            let signature: Ed25519Signature = keypair.sign(&file_hash);
            SignatureResult::Ed25519(signature)
        },
        Algorithm::RSA2048 => {
            let secret_key_bytes = persona.get_rsa_sk().expect("RSA secret key not found");
            let private_key = RsaPrivateKey::from_pkcs1_der(secret_key_bytes).expect("Failed to parse RSA private key");
            let padding = PaddingScheme::new_pkcs1v15_sign(Some(Sha256::new()));
            let signature = private_key.sign(padding, &file_hash).expect("RSA signing failed");
            SignatureResult::RSA(signature)
        },
        Algorithm::ECDSAP256 => {
            let secret_key_bytes = persona.get_ecdsa_sk().expect("ECDSA secret key not found");
            let signing_key = P256SigningKey::from_bytes(secret_key_bytes).expect("Failed to create ECDSA signing key");
            let signature = signing_key.sign(&file_hash);
            SignatureResult::ECDSA(signature.to_der().as_bytes().to_vec())
        },
    };

    // Convert signature into Vec<u8> if necessary
    let signature_bytes = match signature {
        SignatureResult::QuantumSafe(sig) => sig.to_bytes(), // Assuming a to_bytes method exists
        SignatureResult::Ed25519(sig) => sig.to_bytes().to_vec(),
        SignatureResult::RSA(sig) => sig,
        SignatureResult::ECDSA(sig) => sig,
    };

    // Generate header
    let header = construct_header(persona, file_hash, signature_bytes.clone(), contents.len(), contents);
    let header_str = serde_json::to_string_pretty(&header)?;

    // Write header contents to output file
    let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
    out_file.write_all(header_str.as_bytes())?;

    Ok(())
}



// pub fn sign(name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
//     // Retrieve the correct persona
//     let persona = wallet.get_persona(&name.to_lowercase())
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // Get the algorithm corresponding to the persona
//     let algorithm = get_sig_algorithm(persona.get_cs_id())?;

//     // Read the file contents
//     let mut in_file = File::open(input)?;
//     let mut contents = Vec::new();
//     in_file.read_to_end(&mut contents)?;
//     let file_hash: Vec<u8> = get_hash(persona.get_cs_id(), &contents)?;

//     // Perform signing based on the algorithm
//     let signature = match algorithm {
//         Algorithm::QuantumSafe(algo) => {
//             // Use OQS to sign
//             let sig = oqs::sig::Sig::new(algo).expect("Failed to create Sig object");
//             let signature = sig.sign(&file_hash, persona.get_sk().unwrap()).expect("Signing failed");
//             SignatureResult::QuantumSafe(signature)
//         },
//         Algorithm::Ed25519 => {
//             // Use Ed25519 to sign
//             // This is a placeholder; you'll need to replace it with actual signing logic
//             let signature = ed25519_dalek::Signature::new(); // Placeholder
//             SignatureResult::Ed25519(signature)
//         },
//         Algorithm::RSA2048 => {
//             // Use RSA to sign
//             // This is a placeholder; you'll need to replace it with actual signing logic
//             let signature = vec![]; // Placeholder
//             SignatureResult::RSA(signature)
//         },
//         Algorithm::ECDSAP256 => {
//             // Use ECDSA to sign
//             // This is a placeholder; you'll need to replace it with actual signing logic
//             let signature = vec![]; // Placeholder
//             SignatureResult::ECDSA(signature)
//         },
//     };

//     // Convert signature into Vec<u8> if necessary
//     let signature_bytes = match signature {
//         SignatureResult::QuantumSafe(sig) => sig.to_bytes(), // Assuming a to_bytes method exists
//         SignatureResult::Ed25519(sig) => sig.to_bytes().to_vec(),
//         SignatureResult::RSA(sig) => sig,
//         SignatureResult::ECDSA(sig) => sig,
//     };

//     // Generate header
//     let header = construct_header(persona, file_hash, signature_bytes, contents.len(), contents);
//     let header_str = serde_json::to_string_pretty(&header)?;

//     // Write header contents to output file
//     let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
//     out_file.write_all(header_str.as_bytes())?;

//     Ok(())
// }



// Verifies fields of a header file
pub fn verify(name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
    // get the correct persona
    let persona = wallet.get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // get the correct corresponding algo based on persona
    let algorithm = get_sig_algorithm(persona.get_cs_id()).unwrap();
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // deserialize header object
    let header = fs::read_to_string(header)?;
    let header: Header = serde_json::from_str(&header)?;

    // read the file
    let mut in_file = File::open(file)?;
    let mut contents = Vec::new();
    let length = in_file.read_to_end(&mut contents)?;

    // verify each field
    header.verify_sender(&persona);
    header.verify_message_len(length);
    header.verify_hash(&contents);
    header.verify_signature(sig_algo, &persona);

    Ok(())
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