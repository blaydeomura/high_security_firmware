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
        assert_eq!(
            self.pk,
            pk,
            "Verification failed: invalid public key"
        );
    }

    // Checks if length field matches actaul length of message
    pub fn verify_message_len(&self) {
        assert_eq!(
            self.length, self.contents.len(),
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

// // removes the signature file associated with a given persona and file.
// pub fn remove_signature(signature_file_name: &str) -> io::Result<()> {
//     let signature_dir = "signatures/";
//     let signature_file_path = Path::new(signature_dir).join(&signature_file_name);

//     println!(
//         "Attempting to remove file at path: {:?}",
//         signature_file_path
//     );

//     // Check if the file exists before attempting to remove it
//     if signature_file_path.exists() {
//         let path_to_remove = signature_file_path.clone();

//         fs::remove_file(path_to_remove).map_err(|e| {
//             eprintln!(
//                 "Failed to remove signature file: {:?}. Error: {}",
//                 signature_file_path, e
//             );
//             io::Error::new(
//                 ErrorKind::Other,
//                 format!("Failed to remove signature file: {}", e),
//             )
//         })
//     } else {
//         Err(io::Error::new(
//             ErrorKind::NotFound,
//             "Signature file does not exist",
//         ))
//     }
// }

// // lists all signature files in the signatures directory.
// pub fn list_signature_files() -> std::io::Result<()> {
//     let signature_dir = "signatures";
//     let paths = fs::read_dir(signature_dir)?;

//     println!("Listing all signature files:");
//     for path in paths {
//         let path = path?.path();
//         if path.is_file() {
//             if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
//                 println!("{}", filename);
//             }
//         }
//     }

//     Ok(())
// }

// // lists all the files in the "files" directory.
// pub fn list_files() -> std::io::Result<()> {
//     let directory_path = Path::new("files");

//     println!("Listing files in directory: {:?}", directory_path.display());
//     let entries = fs::read_dir(directory_path)?
//         .map(|res| res.map(|e| e.path()))
//         .collect::<Result<Vec<_>, std::io::Error>>()?;

//     // Attempt to create a PathBuf from the "files" directory to use for stripping
//     let base_path = PathBuf::from(directory_path);

//     for entry in entries {
//         if entry.is_file() {
//             // use the strip_prefix method to remove the "files" part from the path
//             // then print the stripped path or the original path if stripping fails
//             match entry.strip_prefix(&base_path) {
//                 Ok(stripped) => println!("{}", stripped.display()),
//                 Err(_) => println!("{}", entry.display()),
//             }
//         }
//     }

//     Ok(())
// }
