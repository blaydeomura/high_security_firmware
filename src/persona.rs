// cs_id: 1 | sig: Dilithium2 | hash: sha256
// cs_id: 2 | sig: Dilithium2 | hash: sha512
// cs_id: 3 | sig: Falcon512 | hash: sha256
// cs_id: 4 | sig: Falcon512 | hash: sha512

use std::io;
use oqs::sig;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha256, Sha512};

#[derive(Serialize, Deserialize, Debug)]
pub struct Persona {
    name: String,
    cs_id: usize,
    pk: sig::PublicKey,
    sk: sig::SecretKey
}

impl Persona {
    pub fn new(name: String, cs_id: usize) -> Self {
        // Initialize sig algorithms
        let sig_algo = get_sig_algorithm(cs_id).unwrap_or_else(|error| { panic!("{}", error) });
        let sig_algo = sig::Sig::new(sig_algo).unwrap_or_else(|_| { panic!("Failed to create signature object")} );

        // Generate sig keypairs
        let (pk, sk) = sig_algo.keypair().unwrap_or_else(|_| { panic!("Failed to generate keypair") });
        
        // Create new persona
        Self {
            name,
            cs_id,
            pk,
            sk
        }
    }

    // Getter for persona name
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    // Getter for the public key
    pub fn get_pk(&self) -> &oqs::sig::PublicKey {
        &self.pk
    }

    // Getter for the secret key
    pub fn get_sk(&self) -> &oqs::sig::SecretKey {
        &self.sk
    }

    // Getter for the cs_id
    pub fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }
}

impl Clone for Persona {
    fn clone(&self) -> Self {
        Persona {
            name: self.name.clone(),
            cs_id: self.cs_id,
            pk: self.pk.clone(),
            sk: self.sk.clone(),
        }
    }
}

// Implements the PartialEq trait for the Persona struct
impl PartialEq for Persona {
    // Defines the eq method, which compares two Persona instances for equality
    fn eq(&self, other: &Self) -> bool {
        // Checks if the names and cs_id fields of the two Persona instances are equal
        self.name == other.name && self.cs_id == other.cs_id
    }
}

// Generates correct signature algorithm based on cs_id
pub fn get_sig_algorithm(cs_id: usize) -> Result<sig::Algorithm, std::io::Error> {
    match cs_id {
        1 | 2 => Ok(sig::Algorithm::Dilithium2),
        3 | 4 => Ok(sig::Algorithm::Falcon512),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-4"))
    }
}

// Generates correct hash output based on cs_id
pub fn get_hash(cs_id: usize, buffer: &Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    match cs_id {
        1 | 3 => {
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            Ok(hasher.finalize().to_vec()) // Convert GenericArray to Vec<u8>
        },
        2 | 4 => {
            let mut hasher = Sha512::new();
            hasher.update(&buffer);
            Ok(hasher.finalize().to_vec()) // Convert GenericArray to Vec<u8>
        },
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-4")),
    }
}
