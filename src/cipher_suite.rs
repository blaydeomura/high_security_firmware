use oqs;
use oqs::{kem, sig};

pub struct Cipher {
    kem: kem::Kem,
    sig: sig::Sig,
}

impl Cipher {
    pub fn new(kem_algo: &str, sig_algo: &str) -> Self {
        let kem_algo = get_kem_algorithm(kem_algo);
        let sig_algo = get_sig_algorithm(sig_algo);

        let kem = kem::Kem::new(kem_algo).expect("Failed to create Kem object");
        let sig = sig::Sig::new(sig_algo).expect("Failed to create Sig object");

        Cipher {
            kem,
            sig,
        }
    }

    pub fn generate_kem_keys(self) -> (kem::PublicKey, kem::SecretKey) {
        self.kem.keypair().expect("Failed to generate keypair")
    }

    pub fn generate_sig_keys(self) -> (sig::PublicKey, sig::SecretKey) {
        self.sig.keypair().expect("Failed to generate keypair")
    }
}

// TODO: throw an error if no strings match
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
