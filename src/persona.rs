// cs_id: 1 | sig: Dilithium2 | hash: sha256
// cs_id: 2 | sig: Dilithium2 | hash: sha512
// cs_id: 3 | sig: Falcon512 | hash: sha256
// cs_id: 4 | sig: Falcon512 | hash: sha512

use std::io;
use oqs::sig;
use serde::{Serialize, Deserialize};

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
}

// Matches cs_id to correct signature algorithm
pub fn get_sig_algorithm(cs_id: usize) -> Result<sig::Algorithm, std::io::Error> {
    match cs_id {
        1 | 2 => Ok(sig::Algorithm::Dilithium2),
        3 | 4 => Ok(sig::Algorithm::Falcon512),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-4"))
    }
}

