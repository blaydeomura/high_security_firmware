// cs_id: 1 | sig: Dilithium2 | hash: sha256
// cs_id: 2 | sig: Dilithium2 | hash: sha512
// cs_id: 3 | sig: Falcon512 | hash: sha256
// cs_id: 4 | sig: Falcon512 | hash: sha512
// ADD IN OTHER CS IDS


use oqs::sig::{self, PublicKey as OqsPublicKey, SecretKey as OqsSecretKey};
use rsa::{RsaPrivateKey, pkcs8::{ToPublicKey, ToPrivateKey}, RsaPublicKey};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer as _, VerifyingKey as P256VerifyingKey};
use ed25519_dalek::{Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};

// Quantum pub key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum QuantumPublicKey {
    Dilithium2(OqsPublicKey),
    Falcon512(OqsPublicKey),
}

// Quantum secret key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum QuantumSecretKey {
    Dilithium2(OqsSecretKey),
    Falcon512(OqsSecretKey),
}

// Regular public key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NonQuantumPublicKey {
    RSA(Vec<u8>), // Storing the RSA public key as bytes
    ECDSA(Vec<u8>), // Storing the ECDSA public key as bytes (P-256 curve)
    EdDSA(Vec<u8>), // Storing the EdDSA public key as bytes (Ed25519)
}

// Regular private key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum NonQuantumSecretKey {
    RSA(Vec<u8>), // Storing the RSA public key as bytes
    ECDSA(Vec<u8>), // Storing the ECDSA public key as bytes (P-256 curve)
    EdDSA(Vec<u8>), // Storing the EdDSA public key as bytes (Ed25519)
}

// Updated Persona struct with fields for both key pairs
#[derive(Serialize, Deserialize, Debug)]
pub struct Persona {
    name: String,
    cs_id: usize,
    quantum_pk: QuantumPublicKey,
    quantum_sk: QuantumSecretKey,
    non_quantum_pk: NonQuantumPublicKey,
    non_quantum_sk: NonQuantumSecretKey,
}

impl Persona {
    // Generate both quantum and non-quantum key pairs
    pub fn new(name: String, cs_id: usize, non_quantum_cs_id: usize) -> Self {
        // Quantum-safe key pair generation
        let (quantum_pk, quantum_sk) = match cs_id {
            1 => {
                let sig_algo = sig::Algorithm::Dilithium2;
                let sig = sig::Sig::new(sig_algo).expect("Failed to create sig object for Dilithium2");
                let (pk, sk) = sig.keypair().expect("Failed to generate keypair for Dilithium2");
                (QuantumPublicKey::Dilithium2(pk), QuantumSecretKey::Dilithium2(sk))
            },
            3 => {
                let sig_algo = sig::Algorithm::Falcon512;
                let sig = sig::Sig::new(sig_algo).expect("Failed to create sig object for Falcon512");
                let (pk, sk) = sig.keypair().expect("Failed to generate keypair for Falcon512");
                (QuantumPublicKey::Falcon512(pk), QuantumSecretKey::Falcon512(sk))
            },
            _ => panic!("Unsupported quantum cs_id"),
        };

        // Non-quantum-safe key pair generation 
        let (non_quantum_pk, non_quantum_sk) = match non_quantum_cs_id {
            5 => { // Example cs_id for RSA
                let mut rng = OsRng;
                let private_key = RsaPrivateKey::new(&mut rng, 2048)
                    .expect("Failed to generate RSA private key");
                let public_key = RsaPublicKey::from(&private_key);

                // Serialize keys to byte vectors for storage
                let pk_der = public_key.to_public_key_der().expect("Failed to serialize RSA public key").as_ref().to_vec();
                let sk_der = private_key.to_pkcs8_der().expect("Failed to serialize RSA private key").as_ref().to_vec();

                (NonQuantumPublicKey::RSA(pk_der), NonQuantumSecretKey::RSA(sk_der))
            },
            6 => { // ECDSA (P-256)
                let mut rng = OsRng;
                let signing_key = P256SigningKey::random(&mut rng);
                let verifying_key = P256VerifyingKey::from(&signing_key);
                let pk_der = verifying_key.to_encoded_point(false).as_bytes().to_vec();
                let sk_der = signing_key.to_bytes().to_vec();
                (NonQuantumPublicKey::ECDSA(pk_der), NonQuantumSecretKey::ECDSA(sk_der))
            },
            7 => { // EdDSA (Ed25519)
                let mut rng = OsRng;
                let keypair = Ed25519Keypair::generate(&mut rng);
                let pk_bytes = keypair.public.to_bytes().to_vec();
                let sk_bytes = keypair.secret.to_bytes().to_vec();
                (NonQuantumPublicKey::EdDSA(pk_bytes), NonQuantumSecretKey::EdDSA(sk_bytes))
            },
            _ => panic!("Unsupported non-quantum cs_id"),
        };

        Ok(Self {
            name,
            cs_id,
            quantum_pk,
            quantum_sk,
            non_quantum_pk,
            non_quantum_sk,
        })
    }

    // Getter for persona name
    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    // Getter for the public key
    pub fn get_quantum_pk(&self) -> &QuantumPublicKey {
        &self.quantum_pk
    }

    // Getter for the secret key
    pub fn get_quantum_sk(&self) -> &QuantumSecretKey {
        &self.quantum_sk
    }

    // Getter for the cs_id
    pub fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    // Getter for the non-quantum public key
    pub fn get_non_quantum_pk(&self) -> &Vec<u8> {
        match &self.non_quantum_pk {
            NonQuantumPublicKey::RSA(bytes) => bytes,
            NonQuantumPublicKey::ECDSA(bytes) => bytes,
            NonQuantumPublicKey::EdDSA(bytes) => bytes,
        }
    }

    // Getter for the non-quantum secret key
    pub fn get_non_quantum_sk(&self) -> &Vec<u8> {
        match &self.non_quantum_sk {
            NonQuantumSecretKey::RSA(bytes) => bytes,
            NonQuantumSecretKey::ECDSA(bytes) => bytes,
            NonQuantumSecretKey::EdDSA(bytes) => bytes,
        }
    }

}

impl Clone for Persona {
    fn clone(&self) -> Self {
        Persona {
            name: self.name.clone(),
            cs_id: self.cs_id,
            quantum_pk: self.quantum_pk.clone(), 
            quantum_sk: self.quantum_sk.clone(), 
            non_quantum_pk: self.non_quantum_pk.clone(), 
            non_quantum_sk: self.non_quantum_sk.clone(), 
        }
    }
}


impl PartialEq for Persona {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.cs_id == other.cs_id
    }
}