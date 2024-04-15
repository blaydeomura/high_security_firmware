use crate::persona::{get_hash, get_sig_algorithm, Persona};
use crate::wallet::Wallet;
use oqs::sig::{PublicKey, Sig, Signature};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::io::{self, Read, Write};
use std::path::Path;
use std::path::PathBuf;

// A struct to store information about a file and its signature
#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    file_type: usize,
    cs_id: usize,
    length: usize,
    file_hash: Vec<u8>,
    signer: PublicKey,
    signature: Signature,
    contents: Vec<u8>,
}

impl Header {
    // Checks if public keys match
    fn verify_sender(&self, persona: &Persona) {
        assert_eq!(
            self.signer,
            Option::expect(persona.get_quantum_pk(), "No public key found"),
            "Verification failed: invalid public key"
        );
    }

    // Checks if length field matches actaul length of message
    fn verify_message_len(&self, length: usize) {
        assert_eq!(
            self.length, length,
            "Verification failed: invalid message length"
        );
    }

    // Checks if hash of file contents matches expected hash
    fn verify_hash(&self, contents: &Vec<u8>) {
        let generated_hash = get_hash(self.cs_id, contents).unwrap();
        assert!(
            do_vecs_match(&generated_hash, &self.file_hash),
            "Verification failed: invalid file contents"
        );
    }

    // Checks if signature is valid
    fn verify_signature(&self, sig_algo: Sig, persona: &Persona) {
        assert!(
            sig_algo
                .verify(
                    &self.file_hash,
                    &self.signature,
                    &Option::expect(persona.get_quantum_pk(), "No public key found")
                )
                .is_ok(),
            "Verification failed: invalid signature"
        );
    }

    // Accessor method for cs_id
    pub fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    // Accessor method for signer
    pub fn get_signer(&self) -> &PublicKey {
        &self.signer
    }
}

// Helper function to check if two vectors are equal
pub fn do_vecs_match<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
    let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
    matching == a.len() && matching == b.len()
}

// Constructs a header with the given information
pub fn construct_header(
    persona: &Persona,
    file_hash: Vec<u8>,
    signature: Signature,
    length: usize,
    contents: Vec<u8>,
) -> Header {
    Header {
        file_type: 1,
        cs_id: persona.get_cs_id(),
        length,
        file_hash,
        signer: Option::expect(persona.get_quantum_pk(), "No quantum key found"),
        signature,
        contents,
    }
}

// Signs a file and construct a header file
pub fn sign(name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
    // get the correct persona
    let persona = wallet
        .get_persona(&name.to_lowercase())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Persona not found"))?;

    // get the algo with the corresponding persona
    let algorithm = get_sig_algorithm(persona.get_cs_id())?;
    let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");

    // read the file
    let mut in_file = File::open(input)?;
    let mut contents = Vec::new();
    let length = in_file.read_to_end(&mut contents)?;

    // hash the file's content and convert the result to Vec<u8> for uniform handling
    let file_hash: Vec<u8> = get_hash(persona.get_cs_id(), &contents)?;

    // signing
    let signature = sig_algo
        .sign(
            &file_hash,
            &Option::expect(persona.get_quantum_sk(), "No quantum sercret key found"),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

    // generate header
    let header = construct_header(persona, file_hash, signature, length, contents);
    let header_str = serde_json::to_string_pretty(&header)?;

    // write header contents to signature file
    let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
    out_file.write(&header_str.as_bytes())?;

    Ok(())
}

// Verifies fields of a header file
pub fn verify(name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
    // get the correct persona
    let persona = wallet
        .get_persona(&name.to_lowercase())
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

    println!(
        "Attempting to remove file at path: {:?}",
        signature_file_path
    );

    // Check if the file exists before attempting to remove it
    if signature_file_path.exists() {
        let path_to_remove = signature_file_path.clone();

        fs::remove_file(path_to_remove).map_err(|e| {
            eprintln!(
                "Failed to remove signature file: {:?}. Error: {}",
                signature_file_path, e
            );
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to remove signature file: {}", e),
            )
        })
    } else {
        Err(io::Error::new(
            ErrorKind::NotFound,
            "Signature file does not exist",
        ))
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
