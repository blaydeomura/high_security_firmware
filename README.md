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
The program uses the Clap library for parsing command-line arguments. The available options are as follows:

* View combination of algorithms in each cipher suite
```
cargo run -- algorithms
```

* Generate persona with specified name and cipher suite
```
cargo run -- generate --name <name> --cs-id <id>
```

* Sign a file using the specified persona
    * Header file must be a json file
```
cargo run -- sign --name <name of signer> --sign <file to sign> --header <header file>
```

* Verify a file based on signer and header file
```
cargo run -- verify --name <name of signer> --sign <signed file> --header <header file>
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

## Examples
* cargo run -- generate --name bob --cs-id 4
* cargo run sign --name bob --file files/file_test.txt
* cargo run verify --name bob --file files/file_test.txt --signature signatures/bob_file_test.txt.sig
* cargo run remove-signature --file bob_file_test.txt.sig
* cargo run remove --name bob
* cargo run list-signatures  


## Testing Core Functionality 
    1. cargo test --test official_test -- --show-output  

## Persistence
- Persona data is stored in wallet directory in json format. 
