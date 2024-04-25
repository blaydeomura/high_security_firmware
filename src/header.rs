use serde::{Deserialize, Serialize};

// A struct to store information about a file and its signature
#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    cs_id: usize,
    file_type: Vec<u8>,
    length: usize,
    file_hash: Vec<u8>,
    pk: Vec<u8>,
}

impl Header {
    // Constructs a header with the given information
    pub fn new(cs_id: usize, length: usize, file_hash: Vec<u8>, pk: Vec<u8>) -> Self {
        Header {
            cs_id,
            file_type: b"SignedData".to_vec(),
            length,
            file_hash,
            pk,
        }
    }

    // Checks if public keys match
    pub fn verify_sender(&self, pk: Vec<u8>) {
        assert_eq!(self.pk, pk, "Verification failed: invalid public key");
    }

    // Checks if hash of file contents matches expected hash
    pub fn verify_hash(&self, hash: &[u8]) {
        assert!(
            do_vecs_match(hash, &self.file_hash),
            "Verification failed: invalid file contents"
        );
    }

    // Method to verify that the file_type is "SignedData"
    pub fn verify_file_type(&self) -> bool {
        self.file_type == b"SignedData".to_vec()
    }

    // Getter method for cs_id
    pub fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    // Getter method for signer
    pub fn get_signer(&self) -> &Vec<u8> {
        &self.pk
    }

    // Getter method for length
    pub fn get_length(&self) -> usize {
        self.length
    }

    // Getter method for hash
    pub fn get_hash(&self) -> &Vec<u8> {
        &self.file_hash
    }

    // Getter method for hash
    pub fn get_pk_bytes(&self) -> &Vec<u8> {
        &self.pk
    }
}

// A struct to store information about a file and its signature
#[derive(Serialize, Deserialize, Debug)]
pub struct SignedData {
    header: Header,
    signature: Vec<u8>,
    contents: Vec<u8>,
}

impl SignedData {
    // Constructs a header with the given information
    pub fn new(header: Header, signature: Vec<u8>, contents: Vec<u8>) -> Self {
        SignedData {
            header,
            signature,
            contents,
        }
    }

    // Checks if length field matches actaul length of message
    pub fn verify_message_len(&self) {
        assert_eq!(
            self.header.length,
            self.contents.len(),
            "Verification failed: invalid message length"
        );
    }

    // Getter method for content
    pub fn get_contents(&self) -> &Vec<u8> {
        &self.contents
    }

    // Getter method for signature
    pub fn get_signature(&self) -> &Vec<u8> {
        &self.signature
    }

    // Getter for header
    pub fn get_header(&self) -> &Header {
        &self.header
    }
}

// Helper function to check if two vectors are equal
pub fn do_vecs_match<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
    matching == a.len() && matching == b.len()
}
