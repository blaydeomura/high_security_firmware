// A cipher suite of quantum safe algorithms from Open Quantum Safe
// Users can select an algorithm for both key exchange and signing

use oqs::{kem, sig};

pub struct Persona {
    name: String,
    kem: kem::Kem,
    sig: sig::Sig,
    kem_keypairs: Vec<(kem::PublicKey, kem::SecretKey)>,
    sig_keypairs: Vec<(sig::PublicKey, sig::SecretKey)>
}

impl Persona {
    pub fn new(name: String, kem_algo: &str, sig_algo: &str) -> Self {
        // Initialize kem and sig algorithms
        let kem_algo = get_kem_algorithm(kem_algo);
        let sig_algo = get_sig_algorithm(sig_algo);
        let kem = kem::Kem::new(kem_algo).expect("Failed to create Kem object");
        let sig = sig::Sig::new(sig_algo).expect("Failed to create Sig object");

        // Generate kem and sig keypairs
        let (kem_pk, kem_sk) = kem.keypair().expect("Failed to generate keypair");
        let mut kem_keypairs = Vec::new();
        kem_keypairs.push((kem_pk, kem_sk));
        let (sig_pk, sig_sk) = sig.keypair().expect("Failed to generate keypair");
        let mut sig_keypairs = Vec::new();
        sig_keypairs.push((sig_pk, sig_sk));
        
        // Create new persona
        Persona {
            name,
            kem,
            sig,
            kem_keypairs,
            sig_keypairs
        }
    }

    fn generate_kem_keys(self) -> (kem::PublicKey, kem::SecretKey) {
        self.kem.keypair().expect("Failed to generate keypair")
    }

    fn generate_sig_keys(self) -> (sig::PublicKey, sig::SecretKey) {
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
