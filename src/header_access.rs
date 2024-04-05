// Inside tests/header_access.rs

// Import necessary modules
use crate::file_ops::Header; // Adjust the path as needed
use ring::rsa::PublicKey;

// Define a trait to access private fields
pub trait HeaderAccess {
    fn get_cs_id(&self) -> usize;
    fn get_signer(&self) -> &PublicKey;
}

// Implement the trait for Header
impl HeaderAccess for Header {
    fn get_cs_id(&self) -> usize {
        self.cs_id
    }

    fn get_signer(&self) -> &PublicKey {
        &self.signer
    }
}
