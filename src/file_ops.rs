use std::fs::File;
use std::io::{self, Read};
use crate::wallet::Wallet;
use std::fs;
use std::path::Path;
use std::io::ErrorKind;
use std::path::PathBuf;
use ed25519_dalek::Signer;
// use oqs::sig::Signature;
// use oqs::sig::Sig;
use oqs::sig::{self, Sig}; // Make sure to import the oqs crate correctly

use crate::persona::{self, Algorithm, Persona};

// This is because each sign function returns something different
enum SignatureResult {
    QuantumSafe(oqs::sig::Signature),
    Ed25519(ed25519_dalek::Signature),
    // add in other two dignatures
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
        Algorithm::RSA2048 => {
            // Placeholder for RSA signing
            todo!()
        },
        Algorithm::ECDSAP256 => {
            // Placeholder for ECDSA signing
            todo!()
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





// pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<Vec<u8>> {
// pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<SignatureResult> {
// // pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {

//     // Retrieve the Persona based on name
//     let persona = wallet.get_persona(&name.to_lowercase())
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // Determine the quantum-safe algorithm to use based on the persona's cs_id
//     let algorithm = persona::get_sig_algorithm(persona.get_cs_id())?;

//     // Open and read the file to be signed
//     let mut file = fs::File::open(file_path)?;
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;

//     // Hash the file's content (Example uses SHA-256 for simplicity)
//     let hash_result_vec: Vec<u8> = persona::get_hash(persona.get_cs_id(), &buffer)?;

//     // Perform the signing operation
//     let signature = match algorithm {
//         persona::Algorithm::QuantumSafe(qs_algo) => {
//             let sig = Sig::new(qs_algo).expect("Failed to create Sig object for quantum-safe algorithm");

//             // Assuming persona.get_quantum_safe_sk_ref() correctly retrieves a reference to the secret key
//             if let Some(sk_ref) = persona.get_quantum_safe_sk_ref() {
//                 // Sign the hashed content using the quantum-safe secret key
//                 sig.sign(&hash_result_vec, sk_ref)
//                     .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
//             } else {
//                 return Err(io::Error::new(io::ErrorKind::NotFound, "Quantum-safe secret key not found"));
//             }
//         },
//         Algorithm::RSA2048 => {
//             // Placeholder for RSA signing
//             todo!()
//         },
//         Algorithm::ECDSAP256 => {
//             // Placeholder for ECDSA signing
//             todo!()
//         },
//         persona::Algorithm::Ed25519 => {
//             // todo!()
//             // let secret_key_bytes = persona
//             //     .get_ed25519_sk_bytes()
//             //     .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Ed25519 secret key not found"))?;
//             // let secret_key = ed25519_dalek::SecretKey::from_bytes(secret_key_bytes)?;
//             // let public_key = ed25519_dalek::PublicKey::from(&secret_key);
//             // let keypair = ed25519_dalek::Keypair { secret: secret_key, public: public_key };
//             // // let ed25519_signature = keypair.sign(&hash_result_vec).as_ref().to_vec();
//             // let ed25519_signature = keypair.sign(&hash_result_vec);
//             // ed25519_signature
//             let secret_key_bytes = persona
//                 .get_ed25519_sk_bytes()
//                 .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Ed25519 secret key not found"))?;
//             let secret_key = ed25519_dalek::SecretKey::from_bytes(secret_key_bytes)?;
//             let keypair = ed25519_dalek::Keypair { secret: secret_key, public: ed25519_dalek::PublicKey::from(&secret_key) };
//             let ed25519_signature = keypair.sign(&hash_result_vec);

//             // Wrap the Ed25519 signature in the enum
//             SignatureResult::Ed25519(ed25519_signature)
//         }

//     };

//     // Write the signature bytes to a file
//     let signature_file_name = format!("{}_{}.sig", &name.to_lowercase(), Path::new(file_path).file_stem().unwrap().to_string_lossy());
//     let signature_dir = "signatures";
//     fs::create_dir_all(signature_dir)?;
//     let signature_file_path = Path::new(signature_dir).join(signature_file_name);
//     fs::write(signature_file_path, &signature)?;

//     Ok((signature.into_vec()))
// }





// pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     let persona = wallet.get_persona(&name.to_lowercase())
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     let algorithm = crate::persona::get_sig_algorithm(persona.get_cs_id())?;

//     // Read the file to be signed
//     let mut file = File::open(file_path)?;
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;

//     let hash_result_vec: Vec<u8> = crate::persona::get_hash(persona.get_cs_id(), &buffer)?;

//     // Signing process according to the algorithm
//     let signature = match algorithm {
//         Algorithm::QuantumSafe(qs_algo) => {
//             let sig = oqs::sig::Sig::new(qs_algo).expect("Failed to create Sig object");
//             // Using the new method to get a direct reference to the SecretKey for quantum-safe algorithms
//             if let Some(sk_ref) = persona.get_quantum_safe_sk_ref() {
//                 sig.sign(&hash_result_vec, sk_ref)
//                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
//             } else {
//                 return Err(io::Error::new(io::ErrorKind::NotFound, "Quantum-safe secret key not found"));
//             }
//         },
//         Algorithm::Ed25519 => {
//             use ed25519_dalek::{Signer, SecretKey, Keypair};
//             let secret_key_bytes = persona.get_ed25519_sk_bytes().ok_or(io::Error::new(io::ErrorKind::NotFound, "Ed25519 secret key not found"))?;
//             let secret_key = SecretKey::from_bytes(secret_key_bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
//             let public_key = persona.get_ed25519_pk_bytes().and_then(|pk| ed25519_dalek::PublicKey::from_bytes(pk).ok()).ok_or(io::Error::new(io::ErrorKind::NotFound, "Ed25519 public key not found"))?;
//             let keypair = Keypair { secret: secret_key, public: public_key };
        
//             let signature = keypair.sign(&hash_result_vec);
//             signature.to_bytes().to_vec()
//         },
//         Algorithm::RSA2048 => {
//             // Placeholder for RSA signing
//             todo!()
//         },
//         Algorithm::ECDSAP256 => {
//             // Placeholder for ECDSA signing
//             todo!()
//         },
//     };

//     // Write the signature bytes to a file
//     let signature_file_name = format!("{}_{}.sig", &name.to_lowercase(), Path::new(file_path).file_stem().unwrap().to_string_lossy());
//     let signature_dir = "signatures";
//     fs::create_dir_all(signature_dir)?;
//     let signature_file_path = Path::new(signature_dir).join(signature_file_name);
//     fs::write(signature_file_path, &signature)?;

//     Ok(())
// }






pub fn verify(name: &str, file_path: &str, signature_file_path: &str, wallet: &Wallet) -> io::Result<()> {
    let persona = wallet.get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    let algorithm = crate::persona::get_sig_algorithm(persona.get_cs_id()).expect("Failed to get signature algorithm");


    // Read the signature file
    let signature_bytes = fs::read(signature_file_path)?;

    // Read and hash the file's content
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let hash_result_vec: Vec<u8> = crate::persona::get_hash(persona.get_cs_id(), &buffer)?;

    // Verification process according to the algorithm
    match algorithm {
        Algorithm::QuantumSafe(qs_algo) => {
            let sig = oqs::sig::Sig::new(qs_algo).expect("Failed to create Sig object");
            let signature_ref = sig.signature_from_bytes(&signature_bytes).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;

            // Use the new method to get a direct reference to the PublicKey for quantum-safe algorithms
            if let Some(pk_ref) = persona.get_quantum_safe_pk_ref() {
                sig.verify(&hash_result_vec, signature_ref, pk_ref)
                   .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?
            } else {
                return Err(io::Error::new(io::ErrorKind::NotFound, "Quantum-safe public key not found"));
            }
        },
        Algorithm::Ed25519 => {
            // Placeholder for Ed25519 verification
            todo!()
        },
        Algorithm::RSA2048 => {
            // Placeholder for RSA verification
            todo!()
        },
        Algorithm::ECDSAP256 => {
            // Placeholder for ECDSA verification
            todo!()
        },
        _ => return Err(io::Error::new(io::ErrorKind::Unsupported, "Unsupported algorithm for verification")),
    }

    Ok(())
}




// pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     // get the correct persona 
//     let persona = wallet.get_persona(&name.to_lowercase())
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // get the algo with the corresponding persona
//     let algorithm = get_sig_algorithm(persona.get_cs_id())?;
//     let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

//     // read the file
//     let mut file = File::open(file_path)?;
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;

//     // hash the file's content and convert the result to Vec<u8> for uniform handling
//     let hash_result_vec: Vec<u8> = get_hash(persona.get_cs_id(), &buffer)?;

//     // signing
//     let signature = sig_algo.sign(&hash_result_vec, persona.get_sk())
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

//     // directly write the signature bytes to a file
//     let signature_file_name = format!("{}_{}.sig", &name.to_lowercase(), Path::new(file_path).file_name().unwrap().to_string_lossy());
//     let signature_dir = "signatures";
//     fs::create_dir_all(signature_dir)?;
//     let signature_file_path = Path::new(signature_dir).join(signature_file_name);
//     fs::write(signature_file_path, &signature)?;

//     Ok(())
// }

// pub fn verify(name: &str, file_path: &str, signature_file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     // get the correct persona
//     let persona = wallet.get_persona(&name.to_lowercase())
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // get the correct corresponding algo based on persona
//     let algorithm = get_sig_algorithm(persona.get_cs_id()).unwrap();
//     let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

//     // read the signature bytes from the file
//     let signature_bytes = std::fs::read(signature_file_path)?;

//     // hash the file's content using the same hash function as was used during signing
//     let mut file = File::open(file_path)?;
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;

//     let hash_result_vec: Vec<u8> = get_hash(persona.get_cs_id(), &buffer)?;

//     // convert raw signature bytes into a SignatureRef for verification
//     let signature_ref = sig_algo.signature_from_bytes(&signature_bytes)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;

//     // perform the verification
//     sig_algo.verify(&hash_result_vec, signature_ref, persona.get_pk())
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Verification failed: {}", e)))?;

//     Ok(())
// }




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