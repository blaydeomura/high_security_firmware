// cs_id: 1 | sig: Dilithium2 | hash: sha256
// cs_id: 2 | sig: Dilithium2 | hash: sha512
// cs_id: 3 | sig: Falcon512 | hash: sha256
// cs_id: 4 | sig: Falcon512 | hash: sha512

use oqs::sig::{self, PublicKey, SecretKey};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use std::io;

use crate::cipher_suite::{self, CipherSuite};

#[derive(Serialize)]
pub struct Persona {
    name: String,
    cs_id: usize,
    cs: Box<dyn CipherSuite>,
}

impl Persona {
    pub fn new(name: String, cs_id: usize) -> Self {
        //let cs = get_ciphersuite(cs_id).unwrap();
        let cs = Box::new(cipher_suite::Dilithium2Sha256::new(name.clone(), cs_id));
        // Create new persona
        Self { name, cs_id, cs }
    }

    // Getter for persona name
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    // Getter for the cs_id
    pub fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        self.cs.hash(buffer)
    }
}

// impl Clone for Persona {
//     fn clone(&self) -> Self {
//         Persona {
//             name: self.name.clone(),
//             cs_id: self.cs_id,
//             cs: self.cs,
//         }
//     }
// }

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
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unsupported cipher suite id. Enter a value between 1-4",
        )),
    }
}

// Generates correct hash output based on cs_id
pub fn get_hash(cs_id: usize, buffer: &Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    match cs_id {
        1 | 3 => {
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            Ok(hasher.finalize().to_vec()) // Convert GenericArray to Vec<u8>
        }
        2 | 4 => {
            let mut hasher = Sha512::new();
            hasher.update(&buffer);
            Ok(hasher.finalize().to_vec()) // Convert GenericArray to Vec<u8>
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unsupported cipher suite id. Enter a value between 1-4",
            ))
        }
    }
}

// pub fn get_ciphersuite(cs_id: usize) -> Result<Box<dyn CipherSuite>, std::io::Error> {
//     match cs_id {
//         1 => {
//             let cs = cipher_suite::Dilithium2Sha256::new();
//             Ok(Box::new(cipher_suite::Dilithium2Sha256::new()))
//         }
//         2 => {
//             let cs = cipher_suite::Dilithium2Sha512::new();
//             Ok(Box::new(cipher_suite::Dilithium2Sha512::new()))
//         }
//         3 => {
//             let cs = cipher_suite::Falcon512Sha256::new();
//             Ok(Box::new(cipher_suite::Falcon512Sha256::new()))
//         }
//         4 => {
//             let cs = cipher_suite::Falcon512Sha512::new();
//             Ok(Box::new(cipher_suite::Falcon512Sha512::new()))
//         }
//         _ => {
//             return Err(io::Error::new(
//                 io::ErrorKind::InvalidInput,
//                 "Unsupported cipher suite id. Enter a value between 1-4",
//             ))
//         }
//     }
// }
