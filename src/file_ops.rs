use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

// removes the signature file associated with a given persona and file.
pub fn remove_signature(signature_file_name: &str) -> io::Result<()> {
    let signature_dir = "signatures/";
    let signature_file_path = Path::new(signature_dir).join(&signature_file_name);

    println!(
        "Attempting to remove file at path: {:?}",
        signature_file_path
    );

    // Check if the file exists before attempting to remove it
    if signature_file_path.exists() {
        let path_to_remove = signature_file_path.clone();

        fs::remove_file(path_to_remove).map_err(|e| {
            eprintln!(
                "Failed to remove signature file: {:?}. Error: {}",
                signature_file_path, e
            );
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to remove signature file: {}", e),
            )
        })
    } else {
        Err(io::Error::new(
            ErrorKind::NotFound,
            "Signature file does not exist",
        ))
    }
}

// lists all signature files in the signatures directory.
pub fn list_signature_files() -> std::io::Result<()> {
    let signature_dir = "signatures";
    let paths = fs::read_dir(signature_dir)?;

    println!("Listing all signature files:");
    for path in paths {
        let path = path?.path();
        if path.is_file() {
            if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                println!("{}", filename);
            }
        }
    }

    Ok(())
}

// lists all the files in the "files" directory.
pub fn list_files() -> std::io::Result<()> {
    let directory_path = Path::new("files");

    println!("Listing files in directory: {:?}", directory_path.display());
    let entries = fs::read_dir(directory_path)?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()?;

    // Attempt to create a PathBuf from the "files" directory to use for stripping
    let base_path = PathBuf::from(directory_path);

    for entry in entries {
        if entry.is_file() {
            // use the strip_prefix method to remove the "files" part from the path
            // then print the stripped path or the original path if stripping fails
            match entry.strip_prefix(&base_path) {
                Ok(stripped) => println!("{}", stripped.display()),
                Err(_) => println!("{}", entry.display()),
            }
        }
    }

    Ok(())
}
