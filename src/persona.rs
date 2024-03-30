// cs_id: 1 | sig: Dilithium2 | hash: sha256
// cs_id: 2 | sig: Dilithium2 | hash: sha512
// cs_id: 3 | sig: Falcon512  | hash: sha256
// cs_id: 4 | sig: Falcon512  | hash: sha512
// cs_id: 5 | sig: Ed25519    | hash: sha256
// cs_id: 6 | sig: RSA        | hash: sha256
// cs_id: 7 | sig: Ecdsa      | hash: sha256

// extern crate ed25519_dalek;

use oqs::sig;
use std::io::{self, ErrorKind};
use rsa::{RsaPrivateKey, RsaPublicKey};
use ring::{rand, signature::{self, KeyPair}};
use p256::ecdsa::SigningKey as EcdsaSigningKey;
use ::rand::rngs::OsRng;
use rsa::pkcs1::EncodeRsaPublicKey;
use sha2::{Digest, Sha256, Sha512};
use serde::{Deserialize, Serialize};
use rsa::pkcs1::EncodeRsaPrivateKey;




#[derive(Serialize, Deserialize, Debug, Clone)]
enum CryptoPublicKey {
    QuantumSafe(sig::PublicKey),
    Ed25519(Vec<u8>), // Serialize the public key for storage
    RSA(Vec<u8>),  
    ECDSA(Vec<u8>),  
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum CryptoPrivateKey {
    QuantumSafe(sig::SecretKey),
    Ed25519(Vec<u8>),
    RSA(Vec<u8>),  // Store the RSA private key as serialized PKCS#8
    ECDSA(Vec<u8>),
}



// struct persona
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Persona {
    name: String,
    cs_id: usize,
    pk: CryptoPublicKey,
    sk: CryptoPrivateKey,
}


impl Persona {
    pub fn new(name: String, cs_id: usize) -> Result<Self, io::Error> {
        // Use the generate_keys function for the specified cs_id
        let (pk, sk) = generate_keys(cs_id)?;

        // Create and return the new persona
        Ok(Self {
            name,
            cs_id,
            pk,
            sk,
        })
    }

    // Getter for persona name
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    // Getter for the public key that tries to return an oqs::sig::PublicKey
    pub fn get_quantum_safe_pk(&self) -> Option<&sig::PublicKey> {
        match &self.pk {
            CryptoPublicKey::QuantumSafe(pk) => Some(pk),
            _ => None,
        }
    }

    // Getter for the private key that tries to return an oqs::sig::SecretKey
    pub fn get_quantum_safe_sk(&self) -> Option<&sig::SecretKey> {
        match &self.sk {
            CryptoPrivateKey::QuantumSafe(sk) => Some(sk),
            _ => None,
        }
    }

    // Getter for RSA public key bytes
    pub fn get_rsa_pk_bytes(&self) -> Option<&[u8]> {
        match &self.pk {
            CryptoPublicKey::RSA(bytes) => Some(bytes),
            _ => None,
        }
    }

    // Getter for the RSA private key
    pub fn get_rsa_sk(&self) -> Option<&[u8]> {
        match &self.sk {
            CryptoPrivateKey::RSA(bytes) => Some(bytes),
            _ => None,
        }
    }

    // Getter for Ed25519 public key bytes
    pub fn get_ed25519_pk_bytes(&self) -> Option<&[u8]> {
        match &self.pk {
            CryptoPublicKey::Ed25519(bytes) => Some(bytes),
            _ => None,
        }
    }

    // Getter for Ed25519 private key bytes
    pub fn get_ed25519_sk_bytes(&self) -> Option<&[u8]> {
        match &self.sk {
            CryptoPrivateKey::Ed25519(bytes) => Some(bytes),
            _ => None,
        }
    }

    // Getter for ECDSA public key bytes
    pub fn get_ecdsa_pk_bytes(&self) -> Option<&[u8]> {
        match &self.pk {
            CryptoPublicKey::ECDSA(bytes) => Some(bytes),
            _ => None,
        }
    }

    // Getter for the ECDSA private key bytes
    pub fn get_ecdsa_sk(&self) -> Option<&[u8]> {
        match &self.sk {
            CryptoPrivateKey::ECDSA(bytes) => Some(bytes),
            _ => None,
        }
    }

    // This method remains unchanged
    pub fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    // MAYBE TAKOUR QUANTUM??
    pub fn get_sk(&self) -> Result<Vec<u8>, io::Error> {
        match &self.sk {
            // return the byte slice as Vec<u8>
            CryptoPrivateKey::QuantumSafe(sk) => Ok(sk.as_ref().to_vec()),
            CryptoPrivateKey::Ed25519(bytes) | CryptoPrivateKey::RSA(bytes) | CryptoPrivateKey::ECDSA(bytes) => Ok(bytes.clone()),
            // Error handling for unsupported or missing keys
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "Secret key not found")),
        }
    }

    // Note: because oqs supports direct signing and verify, we need to have seperate getters for pk and sk depending on algo
    pub fn get_quantum_safe_sk_ref(&self) -> Option<&sig::SecretKey> {
        match &self.sk {
            CryptoPrivateKey::QuantumSafe(sk) => Some(sk),
            _ => None,
        }
    }

    pub fn get_quantum_safe_pk_ref(&self) -> Option<&sig::PublicKey> {
        match &self.pk {
            CryptoPublicKey::QuantumSafe(pk) => Some(pk),
            _ => None,
        }
    }

    // Method to retrieve the public key in Vec<u8> format
    pub fn get_pk(&self) -> Result<Vec<u8>, io::Error> {
        match &self.pk {
            // For quantum-safe keys, assuming `to_bytes` method exists for serialization
            CryptoPublicKey::QuantumSafe(pk) => Ok(pk.as_ref().to_vec()),
            CryptoPublicKey::Ed25519(bytes) | CryptoPublicKey::RSA(bytes) | CryptoPublicKey::ECDSA(bytes) => Ok(bytes.clone()),
            // Error handling for unsupported or missing keys
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "Public key not found")),
        }
    }
    
}

fn generate_keys(cs_id: usize) -> Result<(CryptoPublicKey, CryptoPrivateKey), io::Error> {
    match cs_id {
        1 | 2 => {
            let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2)
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?; // Convert the error type;
            let (pk, sk) = sigalg.keypair()
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;
            Ok((CryptoPublicKey::QuantumSafe(pk), CryptoPrivateKey::QuantumSafe(sk)))
        },
        3 | 4 => {
            let sigalg = sig::Sig::new(sig::Algorithm::Falcon512)
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?; // Convert the error type;
            let (pk, sk) = sigalg.keypair()
                .map_err(|e| io::Error::new(ErrorKind::Other, e.to_string()))?;
            Ok((CryptoPublicKey::QuantumSafe(pk), CryptoPrivateKey::QuantumSafe(sk)))
        },
        5 => {
            // https://docs.rs/ring/latest/ring/signature/index.html 

            let rng = rand::SystemRandom::new();
            let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

            // Serialize the public key for storage
            let public_key_bytes = key_pair.public_key().as_ref().to_vec();
            // Store the PKCS#8 private key bytes directly
            let private_key_bytes = pkcs8_bytes.as_ref().to_vec();
            Ok((CryptoPublicKey::Ed25519(public_key_bytes), CryptoPrivateKey::Ed25519(private_key_bytes)))
        },
        6 => {
            // let mut rng = OsRng{};
            // let bits = 2048;
            // let private_key = RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate a key");
            // let public_key = RsaPublicKey::from(&private_key);
            // let pk_der = public_key.to_pkcs1_der().expect("Failed to serialize public key").as_ref().to_vec();

            // Ok((CryptoPublicKey::RSA(pk_der), CryptoPrivateKey::RSA(private_key)))


            let mut rng = OsRng::default();
            let bits = 2048;
            let private_key = RsaPrivateKey::new(&mut rng, bits)
                .expect("Failed to generate a key");
            let public_key = RsaPublicKey::from(&private_key);
        
            let pk_der = public_key.to_pkcs1_der()
                .expect("Failed to serialize public key")
                .to_vec();
        
            
            //https://docs.rs/pkcs8/latest/pkcs8/struct.SecretDocument.html
            let sk_der = private_key.to_pkcs1_der()
                .expect("Failed to serialize private key")
                .to_bytes()
                .to_vec();
        
            Ok((CryptoPublicKey::RSA(pk_der), CryptoPrivateKey::RSA(sk_der)))
        

        },
        7 => {
            let mut _rng = OsRng::default();
            let signing_key = EcdsaSigningKey::random(&mut OsRng{});  // Generate a new ECDSA signing key
            let verify_key = signing_key.verifying_key(); // Derive the corresponding verifying (public) key

            // Serialize the verifying (public) key to an uncompressed form
            let vk_der = verify_key.to_encoded_point(false).as_bytes().to_vec();

            //-----NEED TO STORE PRIVATE KEYS SAFELY------
            let sk_bytes = signing_key.to_bytes();

            Ok((CryptoPublicKey::ECDSA(vk_der), CryptoPrivateKey::ECDSA(sk_bytes.to_vec())))
            
        },
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id")),
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

pub fn get_hash(cs_id: usize, buffer: &Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    match cs_id {
        1 | 3 | 5 | 6 | 7 => {
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

// For choosing the right signature algorithms
pub enum Algorithm {
    QuantumSafe(oqs::sig::Algorithm),
    Ed25519,
    RSA2048,
    ECDSAP256,
}

// Generates correct signature algorithm based on cs_id
pub fn get_sig_algorithm(cs_id: usize) -> Result<Algorithm, std::io::Error> {
    match cs_id {
        1 => Ok(Algorithm::QuantumSafe(oqs::sig::Algorithm::Dilithium2)),
        2 => Ok(Algorithm::QuantumSafe(oqs::sig::Algorithm::Falcon512)),
        5 => Ok(Algorithm::Ed25519),
        6 => Ok(Algorithm::RSA2048),
        7 => Ok(Algorithm::ECDSAP256),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id")),
    }
}
















// use std::io;
// use oqs::sig;
// use serde::{Serialize, Deserialize};
// use sha2::{Digest, Sha256, Sha512};

// #[derive(Serialize, Deserialize, Debug)]
// pub struct Persona {
//     name: String,
//     cs_id: usize,
//     pk: sig::PublicKey,
//     sk: sig::SecretKey
// }

// impl Persona {
//     pub fn new(name: String, cs_id: usize) -> Self {
//         // Initialize sig algorithms
//         let sig_algo = get_sig_algorithm(cs_id).unwrap_or_else(|error| { panic!("{}", error) });
//         let sig_algo = sig::Sig::new(sig_algo).unwrap_or_else(|_| { panic!("Failed to create signature object")} );

//         // Generate sig keypairs
//         let (pk, sk) = sig_algo.keypair().unwrap_or_else(|_| { panic!("Failed to generate keypair") });
        
//         // Create new persona
//         Self {
//             name,
//             cs_id,
//             pk,
//             sk
//         }
//     }

//     // Getter for persona name
//     pub fn get_name(&self) -> String {
//         self.name.clone()
//     }

//     // Getter for the public key
//     pub fn get_pk(&self) -> &oqs::sig::PublicKey {
//         &self.pk
//     }

//     // Getter for the secret key
//     pub fn get_sk(&self) -> &oqs::sig::SecretKey {
//         &self.sk
//     }

//     // Getter for the cs_id
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
//         }
//     }
// }

// // Implements the PartialEq trait for the Persona struct
// impl PartialEq for Persona {
//     // Defines the eq method, which compares two Persona instances for equality
//     fn eq(&self, other: &Self) -> bool {
//         // Checks if the names and cs_id fields of the two Persona instances are equal
//         self.name == other.name && self.cs_id == other.cs_id
//     }
// }

// // Generates correct signature algorithm based on cs_id
// pub fn get_sig_algorithm(cs_id: usize) -> Result<sig::Algorithm, std::io::Error> {
//     match cs_id {
//         1 | 2 => Ok(sig::Algorithm::Dilithium2),
//         3 | 4 => Ok(sig::Algorithm::Falcon512),
//         _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-4"))
//     }
// }

// // Generates correct hash output based on cs_id
// pub fn get_hash(cs_id: usize, buffer: &Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
//     match cs_id {
//         1 | 3 => {
//             let mut hasher = Sha256::new();
//             hasher.update(&buffer);
//             Ok(hasher.finalize().to_vec()) // Convert GenericArray to Vec<u8>
//         },
//         2 | 4 => {
//             let mut hasher = Sha512::new();
//             hasher.update(&buffer);
//             Ok(hasher.finalize().to_vec()) // Convert GenericArray to Vec<u8>
//         },
//         _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-4")),
//     }
// }