// cs_id: 1 | sig: Dilithium2 | hash: sha256
// cs_id: 2 | sig: Dilithium2 | hash: sha512
// cs_id: 3 | sig: Falcon512 | hash: sha256
// cs_id: 4 | sig: Falcon512 | hash: sha512
// ADD IN OTHER CS IDS


// use oqs::sig::{self, PublicKey as OqsPublicKey, SecretKey as OqsSecretKey};
// use rsa::{RsaPrivateKey, pkcs8::{ToPublicKey, ToPrivateKey}, RsaPublicKey};
// use rand::rngs::OsRng;
// use serde::{Serialize, Deserialize};
// use p256::ecdsa::{SigningKey as P256SigningKey, signature::Signer as _, VerifyingKey as P256VerifyingKey};
// use ed25519_dalek::{Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, SecretKey as Ed25519SecretKey};
use oqs::sig::{self, PublicKey as OqsPublicKey, SecretKey as OqsSecretKey};
// Ensure the rsa crate in Cargo.toml includes necessary features
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePrivateKey, EncodePublicKey}};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
// Correct usage of p256 and ed25519_dalek crates
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use ed25519_dalek::Keypair as Ed25519Keypair;
use sha2::Sha256;
use sha2::Sha512;
use std::io;
use ed25519_dalek::Digest;


#[derive(Serialize, Deserialize, Debug, Clone)]
enum NonQuantumAlgorithm {
    RSA2048,
    ECDSAP256,
    EdDSAEd25519,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum AlgorithmType {
    QuantumSafe(sig::Algorithm),
    NonQuantumSafe(NonQuantumAlgorithm),
}

// Quantum pub key
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum QuantumPublicKey {
    Dilithium2(OqsPublicKey),
    Falcon512(OqsPublicKey),
    // ed generation
    // ecdsa
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
            // 5-8 non quantum
        };

        // Non-quantum-safe key pair generation 
        let (non_quantum_pk, non_quantum_sk) = match non_quantum_cs_id {
            5 => { // Example cs_id for RSA
                let mut rng = OsRng;
                let private_key = RsaPrivateKey::new(&mut rng, 2048)
                    .expect("Failed to generate RSA private key");
                let public_key = RsaPublicKey::from(&private_key);
                
                // Serialize the RSA public key to DER format as Vec<u8>
                let pk_der = public_key.to_public_key_der()
                    .expect("Failed to serialize RSA public key to DER")
                    .to_vec(); // Convert directly to Vec<u8> for the public key
                
                // // Serialize the RSA private key to DER format as Vec<u8>
                // let sk_der = private_key.to_pkcs8_der()
                //     .expect("Failed to serialize RSA private key to DER")
                //     .to_bytes(); // Convert the SecretDocument to Zeroizing<Vec<u8>>
                
                // (NonQuantumPublicKey::RSA(pk_der), NonQuantumSecretKey::RSA(sk_der))
                let sk_der_result = private_key.to_pkcs8_der()
                    .expect("Failed to serialize RSA private key to DER");
                let sk_der_zeroizing = sk_der_result.to_bytes(); // Keep it in Zeroizing<Vec<u8>>

                let sk_der_cloned = sk_der_zeroizing.clone(); // Cloning as Vec<u8>, only if necessary

                (NonQuantumPublicKey::RSA(pk_der), NonQuantumSecretKey::RSA(sk_der_cloned))


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

        Self {
            name,
            cs_id,
            quantum_pk,
            quantum_sk,
            non_quantum_pk,
            non_quantum_sk,
        }
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

// Function to generate the correct hash output based on cs_id
pub fn get_hash(cs_id: usize, buffer: &[u8]) -> Result<Vec<u8>, io::Error> {
    match cs_id {
        1 | 3 | 5 | 6 | 7 => {
            // Quantum-safe algorithms and non-quantum (RSA, ECDSA, EdDSA) using SHA-256
            let mut hasher = Sha256::new();
            hasher.update(buffer);
            Ok(hasher.finalize().to_vec())
        },
        2 | 4 => {
            // Quantum-safe algorithms using SHA-512
            let mut hasher = Sha512::new();
            hasher.update(buffer);
            Ok(hasher.finalize().to_vec())
        },
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-7")),
    }
}

pub fn get_sig_algorithm(cs_id: usize) -> Result<AlgorithmType, io::Error> {
    match cs_id {
        1 | 2 => Ok(AlgorithmType::QuantumSafe(sig::Algorithm::Dilithium2)),
        3 | 4 => Ok(AlgorithmType::QuantumSafe(sig::Algorithm::Falcon512)),
        5 => Ok(AlgorithmType::NonQuantumSafe(NonQuantumAlgorithm::RSA2048)),
        6 => Ok(AlgorithmType::NonQuantumSafe(NonQuantumAlgorithm::ECDSAP256)),
        7 => Ok(AlgorithmType::NonQuantumSafe(NonQuantumAlgorithm::EdDSAEd25519)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "Unsupported cipher suite id. Enter a value between 1-7")),
    }
}
