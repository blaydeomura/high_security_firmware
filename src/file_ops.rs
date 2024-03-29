use oqs::sig::Sig;
use std::fs::File;
use std::io::{self, Read};
use crate::wallet::Wallet;
use crate::persona::get_hash;
use std::fs;
use std::path::Path;
use std::io::ErrorKind;
use std::path::PathBuf;

pub fn sign(name: &str, file_path: &str, wallet: &Wallet) -> io::Result<()> {
    // get the correct persona 
    let persona = wallet.get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // get the algo with the corresponding persona
    let algorithm = get_sig_algorithm(persona.get_cs_id())?;
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // read the file
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // hash the file's content and convert the result to Vec<u8> for uniform handling
    let hash_result_vec: Vec<u8> = get_hash(persona.get_cs_id(), &buffer)?;

    // signing
    let signature = sig_algo.sign(&hash_result_vec, persona.get_sk())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

    // directly write the signature bytes to a file
    let signature_file_name = format!("{}_{}.sig", &name.to_lowercase(), Path::new(file_path).file_name().unwrap().to_string_lossy());
    let signature_dir = "signatures";
    fs::create_dir_all(signature_dir)?;
    let signature_file_path = Path::new(signature_dir).join(signature_file_name);
    fs::write(signature_file_path, &signature)?;

    Ok(())
}

pub fn verify(name: &str, file_path: &str, signature_file_path: &str, wallet: &Wallet) -> io::Result<()> {
    // get the correct persona
    let persona = wallet.get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // get the correct corresponding algo based on persona
    let algorithm = get_sig_algorithm(persona.get_cs_id()).unwrap();
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // read the signature bytes from the file
    let signature_bytes = std::fs::read(signature_file_path)?;

    // hash the file's content using the same hash function as was used during signing
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let hash_result_vec: Vec<u8> = get_hash(persona.get_cs_id(), &buffer)?;

    // convert raw signature bytes into a SignatureRef for verification
    let signature_ref = sig_algo.signature_from_bytes(&signature_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid signature bytes"))?;

    // perform the verification
    sig_algo.verify(&hash_result_vec, signature_ref, persona.get_pk())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Verification failed: {}", e)))?;

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