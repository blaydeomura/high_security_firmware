use crate::header::Header;
use erased_serde::serialize_trait_object;
use oqs::sig::{self, Algorithm, PublicKey, SecretKey, Sig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
};

pub trait CipherSuite: erased_serde::Serialize {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8>;
    fn sign(&self, input: &str, output: &str) -> io::Result<()>;
    fn verify(&self, header: &str) -> io::Result<()>;
    fn get_name(&self) -> &String;
    fn get_pk_bytes(&self) -> Vec<u8>;
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

// Boilerplate function for quantum signing
fn quantum_sign(cs_id: usize, contents: Vec<u8>, file_hash: Vec<u8>, length: usize, output: &str, sig_algo: Sig, pk_bytes: Vec<u8>, sk: &SecretKey) -> io::Result<()> {
    // Sign file
    let signature = sig_algo
        .sign(&file_hash, sk)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;
    let signature = signature.into_vec();

    // Construct header
    let header = Header::new(
        cs_id,
        file_hash,
        pk_bytes,
        signature,
        length,
        contents,
    );
    let header_str = serde_json::to_string_pretty(&header)?;

    // Write header contents to signature file
    let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
    out_file.write(header_str.as_bytes())?;

    Ok(())
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

    pub fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }
}

impl CipherSuite for Dilithium2Sha256 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha256_hash(buffer)
    }

    fn sign(&self, input: &str, output: &str) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Dilithium2).expect("Unable to create sig object");

        // Sign file
        quantum_sign(self.cs_id, contents, file_hash, length, output, sig_algo, self.get_pk_bytes(), &self.sk)
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header =
            serde_json::from_str(&header)?;

        // Verify sender and message length
        header.verify_sender(self.get_pk_bytes());
        header.verify_message_len();

        // Verify hash
        let contents = header.get_contents();
        let hash = self.hash(contents);
        header.verify_hash(&hash);

        // Verify signature
        let sig_algo = Sig::new(Algorithm::Dilithium2).expect("Failed to create sig object");
        let signature_bytes = header.get_signature();
        let signature = sig_algo.signature_from_bytes(signature_bytes).unwrap();
        let pk_bytes = header.get_signer();
        let pk = sig_algo.public_key_from_bytes(pk_bytes).unwrap();
        sig_algo.verify(&hash, signature, pk).expect("OQS error: Verification failed");
        Ok(())
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
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

    pub fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }
}

impl CipherSuite for Dilithium2Sha512 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha512_hash(buffer)
    }

    fn sign(&self, input: &str, output: &str) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Dilithium2).expect("Unable to create sig object");

        // Sign file
        quantum_sign(self.cs_id, contents, file_hash, length, output, sig_algo, self.get_pk_bytes(), &self.sk)
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header =
            serde_json::from_str(&header)?;

        // Verify sender and message length
        header.verify_sender(self.get_pk_bytes());
        header.verify_message_len();

        // Verify hash
        let contents = header.get_contents();
        let hash = self.hash(contents);
        header.verify_hash(&hash);

        // Verify signature
        let sig_algo = Sig::new(Algorithm::Dilithium2).expect("Failed to create sig object");
        let signature_bytes = header.get_signature();
        let signature = sig_algo.signature_from_bytes(signature_bytes).unwrap();
        let pk_bytes = header.get_signer();
        let pk = sig_algo.public_key_from_bytes(pk_bytes).unwrap();
        sig_algo.verify(&hash, signature, pk).expect("OQS error: Verification failed");
        Ok(())
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
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

    pub fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }
}

impl CipherSuite for Falcon512Sha256 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha256_hash(buffer)
    }

    fn sign(&self, input: &str, output: &str) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Falcon512).expect("Unable to create sig object");

        // Sign file
        quantum_sign(self.cs_id, contents, file_hash, length, output, sig_algo, self.get_pk_bytes(), &self.sk)
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header =
            serde_json::from_str(&header)?;

        // Verify sender and message length
        header.verify_sender(self.get_pk_bytes());
        header.verify_message_len();

        // Verify hash
        let contents = header.get_contents();
        let hash = self.hash(contents);
        header.verify_hash(&hash);

        // Verify signature
        let sig_algo = Sig::new(Algorithm::Falcon512).expect("Failed to create sig object");
        let signature_bytes = header.get_signature();
        let signature = sig_algo.signature_from_bytes(signature_bytes).unwrap();
        let pk_bytes = header.get_signer();
        let pk = sig_algo.public_key_from_bytes(pk_bytes).unwrap();
        sig_algo.verify(&hash, signature, pk).expect("OQS error: Verification failed");
        Ok(())
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
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

    pub fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }
}

impl CipherSuite for Falcon512Sha512 {
    fn hash(&self, buffer: &Vec<u8>) -> Vec<u8> {
        sha512_hash(buffer)
    }

    fn sign(&self, input: &str, output: &str) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Falcon512).expect("Unable to create sig object");

        // Sign file
        quantum_sign(self.cs_id, contents, file_hash, length, output, sig_algo, self.get_pk_bytes(), &self.sk)
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header =
            serde_json::from_str(&header)?;

        // Verify sender and message length
        header.verify_sender(self.get_pk_bytes());
        header.verify_message_len();

        // Verify hash
        let contents = header.get_contents();
        let hash = self.hash(contents);
        header.verify_hash(&hash);

        // Verify signature
        let sig_algo = Sig::new(Algorithm::Falcon512).expect("Failed to create sig object");
        let signature_bytes = header.get_signature();
        let signature = sig_algo.signature_from_bytes(signature_bytes).unwrap();
        let pk_bytes = header.get_signer();
        let pk = sig_algo.public_key_from_bytes(pk_bytes).unwrap();
        sig_algo.verify(&hash, signature, pk).expect("OQS error: Verification failed");
        Ok(())
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
    }
}
