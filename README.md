# Shared repo for High Security Firmware

# Encrypted Wallet Manager

## Overview
- This Rust program is a command-line tool for managing a wallet of ciphersuite objects. A ciphersuite object consists of a name and a key pair generated using quantum safe algorithms. Users can generate and remove ciphersuites as well as sign and verify files using the key pairs stored.

## Features
- Generate: Generate a new key pair using the specified algorithm.
- Remove: Remove an existing key pair from the wallet.
- Sign: Signs a file with a secret key.
- Verify: Verifies a file using public key and signature provided.


## Usage
The program uses the Clap library for parsing command-line arguments. The available options are as follows:

* View combination of algorithms in each cipher suite
```
cargo run -- algorithms
```

* Generate a new ciphersuite with the specified algorithms
```
cargo run -- generate --name <name> --cs-id <id>
```

* Sign a file using the specified persona
    * Header file must be a json file
```
cargo run -- sign --name <name of signer> --file <file to sign> --output <header file>
```

* Verify a file based on signer and header file
```
cargo run -- verify --name <name of signer> --header <header file>
```

* Remove a persona from wallet
```
cargo run -- remove --name <name>
```

* Remove signature file
```
cargo run -- remove-signature --file <path to signature file>
```

* List signature files
```
cargo run -- list-signatures
```
* List of files to sing
```
cargo run -- list-files
```

## Quantum Example
* cargo run -- generate --name bob --cs-id 1
* cargo run sign --name bob --file files/file_test.txt --output ./signature_paths_directory/bob_sig_path.json
* cargo run verify --name bob --header ./signature_paths_directory/bob_sig_path.json
* cargo run remove-signature --file bob_file_test.txt.sig
* cargo run remove --name bob
* cargo run list-signatures  

## Non quantum Example
* cargo run -- generate --name mallory --cs-id 5 //good
* cargo run sign --name mallory --file files/file_test.txt --output ./signature_paths_directory/mallory_sig_path.json
* cargo run verify --name mallory --header ./signature_paths_directory/mallory_sig_path.json

## Testing Core Functionality 
    1. cargo test --test official_test -- --show-output  

## Persistence
- Persona data is stored in wallet directory in json format. 
