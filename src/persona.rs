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
        let sig_algo = get_sig_algorithm(cs_id);
        let sig_algo = sig::Sig::new(sig_algo).expect("Failed to create Sig object");

        // Generate sig keypairs
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keys");
        
        // Create new persona
        Persona {
            name,
            cs_id,
            pk,
            sk
        }
    }

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

// TODO: throw an error if no strings match
pub fn get_sig_algorithm(cs_id: usize) -> sig::Algorithm {
    match cs_id {
        1 => sig::Algorithm::Dilithium2,
        2 => sig::Algorithm::Dilithium2,
        3 => sig::Algorithm::Falcon512,
        4 => sig::Algorithm::Falcon512,
        _ => sig::Algorithm::Dilithium2
    }
}
