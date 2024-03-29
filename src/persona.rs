// use std::io;
// use oqs::sig;
// use serde::{Serialize, Deserialize};
// use sha2::{Digest, Sha256, Sha512};

// // Define the HashFunction enum
// #[derive(Debug, Serialize, Deserialize, Clone)] 
// pub enum HashFunction {
//     Sha256,
//     Sha512,
// }

// // Define the CipherSuiteType enum
// #[derive(Debug, Serialize, Deserialize, Clone)] 
// pub enum CipherSuiteType {
//     Dilithium2,
//     Falcon512,
// }

// // Define the CipherSuite struct to hold information about the cipher suite
// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct CipherSuite {
//     cipher_type: CipherSuiteType,
//     hash_function: HashFunction,
// }

// impl CipherSuite {
//     pub fn new(cipher_type: CipherSuiteType, hash_function: HashFunction) -> Self {
//         CipherSuite {
//             cipher_type,
//             hash_function,
//         }
//     }
// }

// // Define the Persona struct to include information about the cipher suite
// #[derive(Serialize, Deserialize, Debug)]
// pub struct Persona {
//     name: String,
//     cs_id: usize,
//     pk: sig::PublicKey,
//     sk: sig::SecretKey,
//     cipher_suite: CipherSuite, // Include the CipherSuite information
// }

// impl Persona {
//     pub fn new(name: String, cs_id: usize) -> Self {
//         // Initialize sig algorithms
//         let sig_algo = get_sig_algorithm(cs_id).unwrap_or_else(|error| { panic!("{}", error) });
//         let sig_algo = sig::Sig::new(sig_algo).unwrap_or_else(|_| { panic!("Failed to create signature object") });

//         // Generate sig keypairs
//         let (pk, sk) = sig_algo.keypair().unwrap_or_else(|_| { panic!("Failed to generate keypair") });

//         // Determine the cipher suite information based on cs_id
//         let cipher_suite = match cs_id {
//             1 | 2 => CipherSuite {
//                 cipher_type: CipherSuiteType::Dilithium2,
//                 hash_function: HashFunction::Sha256,
//             },
//             3 | 4 => CipherSuite {
//                 cipher_type: CipherSuiteType::Falcon512,
//                 hash_function: HashFunction::Sha512,
//             },
//             _ => panic!("Unsupported cipher suite id. Enter a value between 1-4"),
//         };

//         // Create new persona
//         Self {
//             name,
//             cs_id,
//             pk,
//             sk,
//             cipher_suite,
//         }
//     }

//     // Getter methods for persona fields
//     pub fn get_name(&self) -> String {
//         self.name.clone()
//     }

//     pub fn get_pk(&self) -> &oqs::sig::PublicKey {
//         &self.pk
//     }

//     pub fn get_sk(&self) -> &oqs::sig::SecretKey {
//         &self.sk
//     }

//     pub fn get_cs_id(&self) -> usize {
//         self.cs_id
//     }

//     pub fn set_name(&mut self, name: String) {
//         self.name = name;
//     }
// }

// impl Clone for Persona {
//     fn clone(&self) -> Self {
//         Persona {
//             name: self.name.clone(),
//             cs_id: self.cs_id,
//             pk: self.pk.clone(),
//             sk: self.sk.clone(),
//             cipher_suite: self.cipher_suite.clone(), // Clone the cipher suite information
//         }
//     }
// }

// // Implements the PartialEq trait for the Persona struct
// impl PartialEq for Persona {
//     fn eq(&self, other: &Self) -> bool {
//         self.name == other.name && self.cs_id == other.cs_id
//     }
// }

// // Function to generate the correct signature algorithm based on cs_id
// pub fn get_sig_algorithm(cs_id: usize) -> Result<sig::Algorithm, io::Error> {
//     match cs_id {
//         1 | 2 => Ok(sig::Algorithm::Dilithium2),
//         3 | 4 => Ok(sig::Algorithm::Falcon512),
//         _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-4")),
//     }
// }

// // Function to generate the correct hash output based on cs_id
// pub fn get_hash(cs_id: usize, buffer: &[u8]) -> Result<Vec<u8>, io::Error> {
//     match cs_id {
//         1 | 3 => {
//             let mut hasher = Sha256::new();
//             hasher.update(buffer);
//             Ok(hasher.finalize().to_vec())
//         },
//         2 | 4 => {
//             let mut hasher = Sha512::new();
//             hasher.update(buffer);
//             Ok(hasher.finalize().to_vec())
//         },
//         _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-4")),
//     }
// }

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