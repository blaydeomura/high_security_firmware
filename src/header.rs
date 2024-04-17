use serde::{Deserialize, Serialize};

// A struct to store information about a file and its signature
#[derive(Serialize, Deserialize, Debug)]
pub struct Header {
    file_type: usize,
    cs_id: usize,
    length: usize,
    file_hash: Vec<u8>,
    pk: Vec<u8>,
    signature: Vec<u8>,
    contents: Vec<u8>,
}

impl Header {
    // Constructs a header with the given information
    pub fn new(
        cs_id: usize,
        file_hash: Vec<u8>,
        pk: Vec<u8>,
        signature: Vec<u8>,
        length: usize,
        contents: Vec<u8>,
    ) -> Self {
        Header {
            file_type: 1,
            cs_id,
            length,
            file_hash,
            pk,
            signature,
            contents,
        }
    }

    // Checks if public keys match
    pub fn verify_sender(&self, pk: Vec<u8>) {
        assert_eq!(self.pk, pk, "Verification failed: invalid public key");
    }

    // Checks if length field matches actaul length of message
    pub fn verify_message_len(&self) {
        assert_eq!(
            self.length,
            self.contents.len(),
            "Verification failed: invalid message length"
        );
    }

    // Checks if hash of file contents matches expected hash
    pub fn verify_hash(&self, hash: &Vec<u8>) {
        assert!(
            do_vecs_match(&hash, &self.file_hash),
            "Verification failed: invalid file contents"
        );
    }

    // Getter method for cs_id
    pub fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    // Getter method for signer
    pub fn get_signer(&self) -> &Vec<u8> {
        &self.pk
    }

    // Getter method for content
    pub fn get_contents(&self) -> &Vec<u8> {
        &self.contents
    }

    // Getter method for signature
    pub fn get_signature(&self) -> &Vec<u8> {
        &self.signature
    }
}

// Helper function to check if two vectors are equal
pub fn do_vecs_match<T: PartialEq>(a: &Vec<T>, b: &Vec<T>) -> bool {
    let matching = a.iter().zip(b.iter()).filter(|&(a, b)| a == b).count();
    matching == a.len() && matching == b.len()
}
