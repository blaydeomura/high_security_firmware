use crate::header::Header;
use oqs::sig::{self, Algorithm, PublicKey, SecretKey, Sig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
};

use rsa::pkcs1::EncodeRsaPublicKey;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256 as rsa_sha2_Sha256;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::RsaPublicKey;
use rsa::{pkcs1v15::Signature, RsaPrivateKey};
use serde;

pub trait CipherSuite {
    fn hash(&self, buffer: &[u8]) -> Vec<u8>;
    fn sign(&self, input: &str, output: &str) -> io::Result<()>;
    fn verify(&self, header: &str) -> io::Result<()>;
    fn get_name(&self) -> &String;
    fn get_pk_bytes(&self) -> Vec<u8>;
    fn get_cs_id(&self) -> usize;
    fn to_enum(&self) -> CS;
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CS {
    CS1(Dilithium2Sha256),
    CS2(Dilithium2Sha512),
    CS3(Falcon512Sha256),
    CS4(Falcon512Sha512),
    CS5(RsaSha256),
}

impl CS {
    pub fn to_box(self) -> Box<dyn CipherSuite> {
        match self {
            CS::CS1(cs) => Box::new(cs),
            CS::CS2(cs) => Box::new(cs),
            CS::CS3(cs) => Box::new(cs),
            CS::CS4(cs) => Box::new(cs),
            CS::CS5(cs) => Box::new(cs),
        }
    }
}

// Creates a new ciphersuite object based on cs_id
pub fn create_ciphersuite(name: String, cs_id: usize) -> Result<CS, io::Error> {
    let lower_name = name.to_lowercase();

    let cs = match cs_id {
        1 => Ok(CS::CS1(Dilithium2Sha256::new(lower_name.clone(), cs_id))),
        2 => Ok(CS::CS2(Dilithium2Sha512::new(lower_name.clone(), cs_id))),
        3 => Ok(CS::CS3(Falcon512Sha256::new(lower_name.clone(), cs_id))),
        4 => Ok(CS::CS4(Falcon512Sha512::new(lower_name.clone(), cs_id))),
        5 => Ok(CS::CS5(RsaSha256::new(lower_name.clone(), cs_id))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unsupported cipher suite id. Enter a value between 1-5",
        )),
    };

    cs
}

// Sha256 hash function
fn sha256_hash(buffer: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}

// Sha512 hash function
fn sha512_hash(buffer: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}

// Blake3 hash function
fn blake3_hash(buffer: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}

// Boilerplate function for quantum signing
fn quantum_sign(
    cs_id: usize,
    contents: Vec<u8>,
    file_hash: Vec<u8>,
    length: usize,
    output: &str,
    sig_algo: Sig,
    pk_bytes: Vec<u8>,
    sk: &SecretKey,
) -> io::Result<()> {
    // Sign file
    let signature = sig_algo
        .sign(&file_hash, sk)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Signing failed: {}", e)))?;
    let signature = signature.into_vec();

    // Construct header
    let header = Header::new(cs_id, file_hash, pk_bytes, signature, length, contents);
    let header_str = serde_json::to_string_pretty(&header)?;

    // Write header contents to signature file
    let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
    Write::write_all(&mut out_file, header_str.as_bytes())?;

    Ok(())
}

fn quantum_verify(
    header: Header,
    pk_bytes: Vec<u8>,
    hash: Vec<u8>,
    sig_algo: Sig,
) -> io::Result<()> {
    // Verify sender, length of message, and hash of message
    header.verify_sender(pk_bytes);
    header.verify_message_len();
    header.verify_hash(&hash);

    // Verify signature
    let signature_bytes = header.get_signature();
    let signature = sig_algo.signature_from_bytes(signature_bytes).unwrap();
    let pk_bytes = header.get_signer();
    let pk = sig_algo.public_key_from_bytes(pk_bytes).unwrap();
    sig_algo
        .verify(&hash, signature, pk)
        .expect("OQS error: Verification failed");
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    fn hash(&self, buffer: &[u8]) -> Vec<u8> {
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
        quantum_sign(
            self.cs_id,
            contents,
            file_hash,
            length,
            output,
            sig_algo,
            self.get_pk_bytes(),
            &self.sk,
        )
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header = serde_json::from_str(&header)?;

        // Re hash contents
        let contents = header.get_contents();
        let hash = self.hash(contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Dilithium2).expect("Failed to create sig object");

        // Verify header fields
        quantum_verify(header, self.get_pk_bytes(), hash, sig_algo)
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
    }

    fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    fn to_enum(&self) -> CS {
        CS::CS1(self.clone())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    fn hash(&self, buffer: &[u8]) -> Vec<u8> {
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
        quantum_sign(
            self.cs_id,
            contents,
            file_hash,
            length,
            output,
            sig_algo,
            self.get_pk_bytes(),
            &self.sk,
        )
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header = serde_json::from_str(&header)?;

        // Re hash contents
        let contents = header.get_contents();
        let hash = self.hash(contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Dilithium2).expect("Failed to create sig object");

        // Verify header fields
        quantum_verify(header, self.get_pk_bytes(), hash, sig_algo)
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
    }

    fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    fn to_enum(&self) -> CS {
        CS::CS2(self.clone())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    fn hash(&self, buffer: &[u8]) -> Vec<u8> {
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
        quantum_sign(
            self.cs_id,
            contents,
            file_hash,
            length,
            output,
            sig_algo,
            self.get_pk_bytes(),
            &self.sk,
        )
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header = serde_json::from_str(&header)?;

        // Re hash contents
        let contents = header.get_contents();
        let hash = self.hash(contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Falcon512).expect("Failed to create sig object");

        // Verify header fields
        quantum_verify(header, self.get_pk_bytes(), hash, sig_algo)
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
    }

    fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    fn to_enum(&self) -> CS {
        CS::CS3(self.clone())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
    fn hash(&self, buffer: &[u8]) -> Vec<u8> {
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
        quantum_sign(
            self.cs_id,
            contents,
            file_hash,
            length,
            output,
            sig_algo,
            self.get_pk_bytes(),
            &self.sk,
        )
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        // Read header file
        let header = fs::read_to_string(header)?;
        let header: Header = serde_json::from_str(&header)?;

        // Re hash contents
        let contents = header.get_contents();
        let hash = self.hash(contents);

        // Create sig object
        let sig_algo = Sig::new(Algorithm::Falcon512).expect("Failed to create sig object");

        // Verify header fields
        quantum_verify(header, self.get_pk_bytes(), hash, sig_algo)
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk().into_vec()
    }

    fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    fn to_enum(&self) -> CS {
        CS::CS4(self.clone())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RsaSha256 {
    name: String,
    cs_id: usize,
    sk: RsaPrivateKey,
    pk: RsaPublicKey,
}

impl RsaSha256 {
    pub fn new(name: String, cs_id: usize) -> Self {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let sk = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pk = RsaPublicKey::from(&sk);

        RsaSha256 {
            name,
            cs_id,
            sk,
            pk,
        }
    }

    pub fn get_pk(&self) -> RsaPublicKey {
        self.pk.clone()
    }
}

impl CipherSuite for RsaSha256 {
    fn hash(&self, buffer: &[u8]) -> Vec<u8> {
        sha256_hash(buffer)
    }

    fn sign(&self, input: &str, output: &str) -> io::Result<()> {
        // Read and hash the input file
        let mut in_file = File::open(input)?;
        let mut contents = Vec::new();
        let length = in_file.read_to_end(&mut contents)?;
        let file_hash: Vec<u8> = self.hash(&contents);

        // Create sig object
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<rsa_sha2_Sha256>::new(self.sk.clone());
        let signature = signing_key.sign_with_rng(&mut rng, &contents);
        let signature = signature.to_vec();

        let header = Header::new(
            self.cs_id,
            file_hash,
            self.pk
                .to_pkcs1_der()
                .expect("Failed to serialize public key")
                .to_vec(),
            signature,
            length,
            contents,
        );
        let header_str = serde_json::to_string_pretty(&header)?;

        let mut out_file = OpenOptions::new().append(true).create(true).open(output)?;
        Write::write_all(&mut out_file, header_str.as_bytes())?;

        Ok(())
    }

    fn verify(&self, header: &str) -> io::Result<()> {
        let header = fs::read_to_string(header)?;
        let header: Header = serde_json::from_str(&header)?;

        // Re hash contents
        let contents = header.get_contents();
        let hash = self.hash(contents);

        // key for signing based off of private key
        let signing_key = SigningKey::<rsa_sha2_Sha256>::new(self.sk.clone());

        // Verify sender, length of message, and hash of message
        header.verify_sender(
            self.pk
                .to_pkcs1_der()
                .expect("Failed to serialize public key")
                .to_vec(),
        );
        header.verify_message_len();
        header.verify_hash(&hash);

        // Verify signature
        let signature_bytes = header.get_signature();
        let signature = Signature::try_from(signature_bytes.as_slice())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

        let verifying_key = signing_key.verifying_key();
        verifying_key
            .verify(contents, &signature)
            .expect("failed to verify");
        Ok(())
    }

    fn get_name(&self) -> &String {
        &self.name
    }

    fn get_pk_bytes(&self) -> Vec<u8> {
        self.get_pk()
            .to_pkcs1_der()
            .expect("Failed to serialize public key")
            .to_vec()
    }

    fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    fn to_enum(&self) -> CS {
        CS::CS5(self.clone())
    }
}
