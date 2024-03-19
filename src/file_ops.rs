use oqs::sig::Sig;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use crate::wallet::Wallet;
use crate::persona::get_sig_algorithm;
use std::fs;
use std::path::Path;
use sha2::Sha512;

// https://docs.rs/oqs/latest/oqs/sig/struct.Sig.html 

//cargo run sign --name blayde --filename files/file_test.txt

pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
    // get the correct persona 
    let persona = wallet.get_persona(name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // get the algo with the corresponding persona
    let algorithm = get_sig_algorithm(persona.get_cs_id());
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // read the file
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // hash the file's content and convert the result to Vec<u8> for uniform handling
    let hash_result_vec: Vec<u8> = match persona.get_cs_id() {
        1 | 3 => {
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            hasher.finalize().to_vec() // Convert GenericArray to Vec<u8>
        },
        2 | 4 => {
            let mut hasher = Sha512::new();
            hasher.update(&buffer);
            hasher.finalize().to_vec() // Convert GenericArray to Vec<u8>
        },
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id")),
    };

    // signing
    let signature = sig_algo.sign(&hash_result_vec, persona.get_sk())
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

    // get the correct corresponding algo based on persona
    let algorithm = get_sig_algorithm(persona.get_cs_id());
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // read the signature bytes from the file
    let signature_bytes = std::fs::read(signature_file_path)?;

    // hash the file's content using the same hash function as was used during signing
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let hash_result_vec: Vec<u8> = match persona.get_cs_id() {
        1 | 3 => {
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            hasher.finalize().to_vec() // convert to Vec<u8> for uniform handling
        },
        2 | 4 => {
            let mut hasher = Sha512::new();
            hasher.update(&buffer);
            hasher.finalize().to_vec() // convert to Vec<u8> for uniform handling
        },
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id")),
    };

    // convert raw signature bytes into a SignatureRef for verification
    let signature_ref = sig_algo.signature_from_bytes(&signature_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;

    // perform the verification
    sig_algo.verify(&hash_result_vec, signature_ref, persona.get_pk())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Verification failed: {}", e)))?;

    Ok(())
}








// pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     let persona = wallet.get_persona(name)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     let algorithm = get_sig_algorithm(persona.get_cs_id());
//     let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

//     let mut file = File::open(file_path)?;
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;

//     // Choose the hashing algorithm based on the cs_id
//     let hash_result = match persona.get_cs_id() {
//         1 | 3 => {
//             let mut hasher = Sha256::new();
//             hasher.update(&buffer);
//             hasher.finalize()
//         },
//         2 | 4 => {
//             let mut hasher = Sha512::new();
//             hasher.update(&buffer);
//             hasher.finalize()
//         },
//         _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id")),
//     };

//     let signature = sig_algo.sign(hash_result.as_slice(), persona.get_sk())
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

//     let signature_file_name = format!("{}_{}.sig", name, Path::new(file_path).file_name().unwrap().to_string_lossy());
//     let signature_dir = "signatures";
//     fs::create_dir_all(signature_dir)?;
//     let signature_file_path = Path::new(signature_dir).join(signature_file_name);
//     fs::write(signature_file_path, &signature)?;

//     Ok(())
// }








// pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     // find the correct persona from wallet
//     let persona = wallet.get_persona(name)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // get the correct cipher suite id algorithm
//     let algorithm = get_sig_algorithm(persona.get_cs_id());
//     let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

//     // hash the file dependin gon cioher suite
//     let mut file = File::open(file_path)?;
//     let mut hasher = Sha256::new();
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;
//     hasher.update(&buffer);
//     let hash_result = hasher.finalize();

//     // sign the signature
//     let signature = sig_algo.sign(hash_result.as_slice(), persona.get_sk())
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

//     // directly write the signature bytes to a file
//     let signature_file_name = format!("{}_{}.sig", name, Path::new(file_path).file_name().unwrap().to_string_lossy());
//     let signature_dir = "signatures";
//     fs::create_dir_all(signature_dir)?;
//     let signature_file_path = Path::new(signature_dir).join(signature_file_name);
//     fs::write(signature_file_path, &signature)?;

//     Ok(())
// }



// pub fn verify(name: &str, file_path: &str, signature_file_path: &str, wallet: &Wallet) -> io::Result<()> {
//     // get the correct persona
//     let persona = wallet.get_persona(name)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

//     // algorithm that corresponds to cipher suite
//     let algorithm = get_sig_algorithm(persona.get_cs_id());
//     let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

//     // get the signature file
//     let signature_file_name = format!("{}_{}.sig", name, Path::new(file_path).file_name().unwrap().to_string_lossy());
//     let signature_dir = "signatures";
//     let signature_file_path = Path::new(signature_dir).join(signature_file_name);

//     let signature_bytes = std::fs::read(signature_file_path)?;

//     // correctly create a SignatureRef from the raw signature bytes
//     let signature_ref = sig_algo.signature_from_bytes(&signature_bytes)
//         .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;

//     // hash file
//     let mut file = File::open(file_path)?;
//     let mut hasher = Sha256::new();
//     let mut buffer = Vec::new();
//     file.read_to_end(&mut buffer)?;
//     hasher.update(&buffer);
//     let hash_result = hasher.finalize();

//     // verify
//     sig_algo.verify(hash_result.as_slice(), signature_ref, persona.get_pk())
//         .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Verification failed: {}", e)))?;

//     Ok(())
// }
