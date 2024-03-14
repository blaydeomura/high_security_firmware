// A cipher suite of quantum safe algorithms from Open Quantum Safe
// Users can select an algorithm for both key exchange and signing

use std::collections::HashMap;
use oqs::{kem, sig};

pub struct Persona {
    name: String,
    sig: sig::Sig,
    sig_pk: sig::PublicKey,
    sig_sk: sig::SecretKey,
    trusted: HashMap<String, kem::SharedSecret>
}

impl Persona {
    pub fn new(&self, name: String, sig_algo: &str) -> Self {
        // Initialize sig algorithms
        let sig_algo = get_sig_algorithm(sig_algo);
        let sig = sig::Sig::new(sig_algo).expect("Failed to create Sig object");

        // Generate sig keypairs
        let (sig_pk, sig_sk) = self.generate_sig_keys();
        
        // Create new persona
        Persona {
            name,
            sig,
            sig_pk,
            sig_sk,
            trusted: HashMap::new()
        }
    }

    fn generate_sig_keys(&self) -> (sig::PublicKey, sig::SecretKey) {
        self.sig.keypair().expect("Failed to generate keypair")
    }
}

// TODO: throw an error if no strings match
// Can add more if we want
fn get_kem_algorithm(kem_algo: &str) -> kem::Algorithm {
    match kem_algo {
        "BikeL1" => kem::Algorithm::BikeL1,
        "BikeL3" => kem::Algorithm::BikeL3,
        "BikeL5" => kem::Algorithm::BikeL5,
        "Kyber512" => kem::Algorithm::Kyber512,
        "Kyber768" => kem::Algorithm::Kyber768,
        "Kyber1024" => kem::Algorithm::Kyber1024,
        _ => kem::Algorithm::Kyber512
    }
}

// TODO: throw an error if no strings match
fn get_sig_algorithm(sig_algo: &str) -> sig::Algorithm {
    match sig_algo {
        "Dilithium2" => sig::Algorithm::Dilithium2,
        "Dilithium3" => sig::Algorithm::Dilithium3,
        "Dilithium5" => sig::Algorithm::Dilithium5,
        "Falcon512" => sig::Algorithm::Falcon512,
        "Falcon1024" => sig::Algorithm::Falcon1024,
        _ => sig::Algorithm::Dilithium2
    }
}

pub fn trade_shared_secret(person_a: &mut Persona, person_b: &mut Persona, kem_algo: &str) {
    // Check that person_a and person_b are using the same algorithms
    if person_a.sig.algorithm() != person_b.sig.algorithm() {
        println!("ERROR! Signature algorithm must be the same for both parties");
        return
    }

    // Generate KEM keypair for exchange
    let kem_algo = get_kem_algorithm(kem_algo);
    let kem_algo = kem::Kem::new(kem_algo).expect("Failed to create KEM");
    let (kem_pk, kem_sk) = kem_algo.keypair().expect("Failed to generate KEM keypair");
    
    // person_a signs kem_pk, sends to person_b
    let a_signature = person_a.sig.sign(kem_pk.as_ref(), &person_a.sig_sk).expect("person_a failed to sign public key");
    
    // Have person_b verify signature
    let verification = person_b.sig.verify(kem_pk.as_ref(), &a_signature, &person_a.sig_pk);
    match verification {
        Ok(()) => { println!("Signature verification successful: person_a sent a valid signature") }
        Err(_) => { println!("Signature verification failed: person_a sent an invalid signature") }
    }

    // person_b encapsulates and signs resulting ciphertext
    let (kem_ct, b_kem_ss) = kem_algo.encapsulate(&kem_pk).expect("Encapsulation failed");
    let b_signature = person_b.sig.sign(kem_ct.as_ref(), &person_b.sig_sk).expect("person_b failed to sign kem_ct");

    // person_a verifies and decapuslates
    let verification = person_a.sig.verify(kem_ct.as_ref(), &b_signature, &person_b.sig_pk);
    match verification {
        Ok(()) => { println!("Signature verification successful: person_b sent a valid signature") }
        Err(_) => { println!("Signature verification failed: person_b sent an invalid signature") }
    }
    let a_kem_ss = kem_algo.decapsulate(&kem_sk, &kem_ct).expect("Decapsulation failed");

    // If shared secrets match, store them in trusted hashmap
    if a_kem_ss == b_kem_ss {
        person_a.trusted.insert(String::from(&person_b.name), a_kem_ss);
        person_b.trusted.insert(String::from(&person_a.name), b_kem_ss);
    } else {
        println!("ERROR: Shared secrets do not match")
    }
} 