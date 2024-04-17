use crate::{file_ops::construct_header, wallet::Wallet};
use erased_serde::serialize_trait_object;
use oqs::sig::{self, Algorithm, PublicKey, SecretKey, Sig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
};

pub trait CipherSuite: erased_serde::Serialize {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8>;
    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()>;
    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()>;
    fn get_name(&self) -> &String;
    fn get_pk_bytes(&self) -> &Vec<u8>;
}
serialize_trait_object!(CipherSuite);

// Sha256 hash function
fn sha256_hash(buffer: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}

// Sha512 hash function
fn sha512_hash(buffer: &Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}

// Blake3 hash function
fn blake3_hash(buffer: &Vec<u8>) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Dilithium2Sha256 {
    name: String,
    cs_id: usize,
    pk: PublicKey,
    sk: SecretKey,
}

impl Dilithium2Sha256 {
    pub fn new(name: String, cs_id: usize) -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Dilithium2).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Dilithium2Sha256 {
            name,
            cs_id,
            pk,
            sk,
        }
    }

    pub fn get_pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn get_sk(&self) -> &SecretKey {
        &self.sk
    }
}

impl CipherSuite for Dilithium2Sha256 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha256_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Sign file
        let algorithm = Algorithm::Dilithium2;
        let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");
        let signature = sig_algo
            .sign(&file_hash, &self.sk)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

        // Construct header
        let header = construct_header(
            self.cs_id,
            file_hash,
            self.pk.into_vec(),
            signature,
            length,
            contents,
        );
        let header_str = serde_json::to_string_pretty(&header)?;

        // write header contents to signature file
        let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
        out_file.write(&header_str.as_bytes())?;

        Ok(())
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> &Vec<u8> {
        &self.pk.into_vec()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dilithium2Sha512 {
    name: String,
    cs_id: usize,
    pk: PublicKey,
    sk: SecretKey,
}

impl Dilithium2Sha512 {
    pub fn new(name: String, cs_id: usize) -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Dilithium2).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Dilithium2Sha512 {
            name,
            cs_id,
            pk,
            sk,
        }
    }

    pub fn get_pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn get_sk(&self) -> &SecretKey {
        &self.sk
    }
}

impl CipherSuite for Dilithium2Sha512 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha512_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Sign file
        let algorithm = Algorithm::Dilithium2;
        let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");
        let signature = sig_algo
            .sign(&file_hash, &self.sk)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

        // Construct header
        let header = construct_header(
            self.cs_id,
            file_hash,
            self.pk.into_vec(),
            signature,
            length,
            contents,
        );
        let header_str = serde_json::to_string_pretty(&header)?;

        // write header contents to signature file
        let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
        out_file.write(&header_str.as_bytes())?;

        Ok(())
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> &Vec<u8> {
        &self.pk.into_vec()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Falcon512Sha256 {
    name: String,
    cs_id: usize,
    pk: PublicKey,
    sk: SecretKey,
}

impl Falcon512Sha256 {
    pub fn new(name: String, cs_id: usize) -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Falcon512).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Falcon512Sha256 {
            name,
            cs_id,
            pk,
            sk,
        }
    }

    pub fn get_pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn get_sk(&self) -> &SecretKey {
        &self.sk
    }
}

impl CipherSuite for Falcon512Sha256 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha256_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Sign file
        let algorithm = Algorithm::Falcon512;
        let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");
        let signature = sig_algo
            .sign(&file_hash, &self.sk)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

        // Construct header
        let header = construct_header(
            self.cs_id,
            file_hash,
            self.pk.into_vec(),
            signature,
            length,
            contents,
        );
        let header_str = serde_json::to_string_pretty(&header)?;

        // write header contents to signature file
        let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
        out_file.write(&header_str.as_bytes())?;

        Ok(())
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> &Vec<u8> {
        &self.pk.into_vec()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Falcon512Sha512 {
    name: String,
    cs_id: usize,
    pk: PublicKey,
    sk: SecretKey,
}

impl Falcon512Sha512 {
    pub fn new(name: String, cs_id: usize) -> Self {
        let sig_algo =
            sig::Sig::new(sig::Algorithm::Falcon512).expect("Failed to create sig object");
        let (pk, sk) = sig_algo.keypair().expect("Failed to generate keypair");

        Falcon512Sha512 {
            name,
            cs_id,
            pk,
            sk,
        }
    }

    pub fn get_pk(&self) -> &PublicKey {
        &self.pk
    }

    pub fn get_sk(&self) -> &SecretKey {
        &self.sk
    }
}

impl CipherSuite for Falcon512Sha512 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha512_hash(buffer)
    }

    fn sign(&self, name: &str, input: &str, output: &str, wallet: &Wallet) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Sign file
        let algorithm = Algorithm::Falcon512;
        let sig_algo = Sig::new(algorithm).expect("Failed to create Sig object");
        let signature = sig_algo
            .sign(&file_hash, &self.sk)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;

        // Construct header
        let header = construct_header(
            self.cs_id,
            file_hash,
            self.pk.into_vec(),
            signature,
            length,
            contents,
        );
        let header_str = serde_json::to_string_pretty(&header)?;

        // write header contents to signature file
        let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
        out_file.write(&header_str.as_bytes())?;

        Ok(())
    }

    fn verify(&self, name: &str, header: &str, file: &str, wallet: &Wallet) -> io::Result<()> {
        todo!()
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> &Vec<u8> {
        &self.pk.into_vec()
    }
}
