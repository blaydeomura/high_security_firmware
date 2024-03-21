# Shared repo for High Security Firmware

# Encrypted Wallet Manager

## Overview
- This Rust program is a command-line tool for managing a wallet of Persona objects. A Persona object consists of a name and a key pair generated using quantum safe algorithms. Users can generate and remove Personas as well as sign and verify files using the key pairs stored.

## Features
- Generate: Generate a new key pair using the specified algorithm.
- Remove: Remove an existing key pair from the wallet.
- Sign: Signs a file with a secret key.
- Verify: Verifies a file using public key and signature provided.


## Usage
- Command Line Options: The program uses the Clap library for parsing command-line arguments. The available options are as follows:

* View supported algorithms in each cipher suite
```cargo run -- algorithms```

* Generate persona with specified name and cipher suite
```cargo run -- generate --name <name> --cs-id <id>```

* Sign a file using the specified persona
```cargo run sign --name <name> --file <path to file>```

* cargo run verify --name <Name of persona> --filename files/<name of file to hash> --signature signatures/<signature of hashed file>
    * verifies a file and which persona + signature file
* cargo run -- remove --name <name of persona>
    * removes persona
* cargo run remove-signature --file <name of signature file to remove>
    * removes signature file
* cargo run list-signatures
    * lists all signature files
* cargo run list-files
    * lists possible files to sign

## example
* cargo run -- generate --name bob --cs-id 4
* cargo run sign --name bob --file files/file_test.txt
* cargo run verify --name bob --file files/file_test.txt --signature signatures/bob_file_test.txt.sig
* cargo run remove-signature --file bob_file_test.txt.sig
* cargo run remove --name bob
* cargo run list-signatures  


# Testing 
    1. cargo test --test file_ops_test
    2. cargo test --test wallet_test


## Persistence
- Persona data is stored in wallet directory in json format. 
