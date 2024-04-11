use crate::wallet::Wallet;
use oqs::sig::{self, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::io;
use erased_serde::serialize_trait_object;

pub trait CipherSuite: erased_serde::Serialize { // CipherSuite
    fn hash(&self, buffer: Vec<u8>) -> Vec<u8>;
    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()>;
    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()>;
}
serialize_trait_object!(CipherSuite);

// Sha256 hash function
fn sha256_hash(buffer: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    hasher.finalize().to_vec() // Convert GenericArray to Vec<u8>
}

// Sha512 hash function
fn sha512_hash(buffer: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(&buffer);
    hasher.finalize().to_vec() // Convert GenericArray to Vec<u8>
}

// Blake3 hash function
fn blake3_hash(buffer: Vec<u8>) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&buffer);
    hasher.finalize().to_vec()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dilithium2Sha256 {
    pk: PublicKey,
    sk: SecretKey,
}

impl Dilithium2Sha256 {
    pub fn new() -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Dilithium2).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Dilithium2Sha256 { pk, sk }
    }

    // pub fn get_pk(&self) -> PublicKey {
    //     self.pk
    // }
}

impl CipherSuite for Dilithium2Sha256 {
    fn hash(&self, buffer: Vec<u8>) -> Vec<u8> {
        sha256_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dilithium2Sha512 {
    pk: PublicKey,
    sk: SecretKey,
}

impl Dilithium2Sha512 {
    pub fn new() -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Dilithium2).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Dilithium2Sha512 { pk, sk }
    }
}

impl CipherSuite for Dilithium2Sha512 {
    fn hash(&self, buffer: Vec<u8>) -> Vec<u8> {
        sha512_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Falcon512Sha256 {
    pk: PublicKey,
    sk: SecretKey,
}

impl Falcon512Sha256 {
    pub fn new() -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Falcon512).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Falcon512Sha256 { pk, sk }
    }
}

impl CipherSuite for Falcon512Sha256 {
    fn hash(&self, buffer: Vec<u8>) -> Vec<u8> {
        sha256_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Falcon512Sha512 {
    pk: PublicKey,
    sk: SecretKey,
}

impl Falcon512Sha512 {
    pub fn new() -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Falcon512).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Falcon512Sha512 { pk, sk }
    }
}

impl CipherSuite for Falcon512Sha512 {
    fn hash(&self, buffer: Vec<u8>) -> Vec<u8> {
        sha512_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }
}
