use oqs::sig::Sig;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use crate::wallet::Wallet;
use crate::persona::get_sig_algorithm;
use std::fs;
use std::path::Path;
use hex;

// https://docs.rs/oqs/latest/oqs/sig/struct.Sig.html 

// pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     // get the correct persona object
//     let persona = wallet.get_persona(name)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // get correct algo from persona and ciphersuite id
//     let algorithm = get_sig_algorithm(persona.get_cs_id());
//     let sig_algo = Sig::new(algorithm)
//         .expect("Failed to create Sig object");

//     // hash the desired file
//     let mut file = File::open(file_path)?;
//     let mut hasher = Sha256::new();
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;
//     hasher.update(&buffer);
//     let hash_result = hasher.finalize();

//     // sign the file
//     let signature = sig_algo.sign(hash_result.as_slice(), persona.get_sk())
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

//     // convert signature to hex string for storage
//     let signature_hex = hex::encode(signature);

//     // write the hex-encoded signature to a file
//     let signature_file_name = format!("{}_{}.sig", name, Path::new(file_path).file_name().unwrap().to_string_lossy());
//     let signature_dir = "signatures";
//     fs::create_dir_all(signature_dir)?; // Create directory if it doesn't exist
//     let signature_file_path = Path::new(signature_dir).join(signature_file_name);
//     fs::write(signature_file_path, signature_hex.as_bytes())?;

//     Ok(())
// }


//cargo run sign --name blayde --filename files/file_test.txt

pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
    // find the correct persona from wallet
    let persona = wallet.get_persona(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // get the correct cipher suite id algorithm
    let algorithm = get_sig_algorithm(persona.get_cs_id());
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // hash the file dependin gon cioher suite
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    let hash_result = hasher.finalize();

    // sign the signature
    let signature = sig_algo.sign(hash_result.as_slice(), persona.get_sk())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

    // directly write the signature bytes to a file
    let signature_file_name = format!("{}_{}.sig", name, Path::new(file_path).file_name().unwrap().to_string_lossy());
    let signature_dir = "signatures";
    fs::create_dir_all(signature_dir)?;
    let signature_file_path = Path::new(signature_dir).join(signature_file_name);
    fs::write(signature_file_path, &signature)?;

    Ok(())
}



pub fn verify(name: &str, file_path: &str, signature_file_path: &str, wallet: &Wallet) -> io::Result<()> {
    // get the correct persona
    let persona = wallet.get_persona(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // algorithm that corresponds to cipher suite
    let algorithm = get_sig_algorithm(persona.get_cs_id());
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // get the signature file
    let signature_file_name = format!("{}_{}.sig", name, Path::new(file_path).file_name().unwrap().to_string_lossy());
    let signature_dir = "signatures";
    let signature_file_path = Path::new(signature_dir).join(signature_file_name);

    let signature_bytes = std::fs::read(signature_file_path)?;

    // correctly create a SignatureRef from the raw signature bytes
    let signature_ref = sig_algo.signature_from_bytes(&signature_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;

    // hash file
    let mut file = File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    let hash_result = hasher.finalize();

    // verify
    sig_algo.verify(hash_result.as_slice(), signature_ref, persona.get_pk())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Verification failed: {}", e)))?;

    Ok(())
}





// pub fn verify(name: &str, file_path: &str, signature_file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     // get correct persona value
//     let persona = wallet.get_persona(name)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // get the algorithm used by persona and corresponding cs_id
//     let algorithm = get_sig_algorithm(persona.get_cs_id());
//     let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

//     // Directly read and decode the signature from the provided file path
//     let signature_hex = fs::read_to_string(signature_file_path)?;
//     let signature_bytes = hex::decode(signature_hex)
//         .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Failed to decode signature: {}", e)))?;

//     // Hash the file's content as done in the sign function
//     let mut file = File::open(file_path)?;
//     let mut hasher = Sha256::new();
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;
//     hasher.update(&buffer);
//     let hash_result = hasher.finalize();

//     // Attempt to convert the signature bytes into a usable format for verification
//     let signature_ref = sig_algo.signature_from_bytes(&signature_bytes)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;

//     // Perform the verification
//     sig_algo.verify(hash_result.as_slice(), signature_ref, persona.get_pk())
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Verification failed: {}", e)))?;

//     Ok(())
// }






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
