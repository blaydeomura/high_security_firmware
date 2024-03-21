# Shared repo for High Security Firmware

# Encrypted Wallet Manager

## Overview
- This Rust program is a command-line tool for managing a wallet of Persona objects. A Persona object consists of a name, public and secret key pair generation, corresponding hashing values, and signing/verifying files.

## Features
- Generate Keys: Generate a new key pair for a person with a specific encryption key.
- Remove Keys: Remove an existing key pair from the wallet.
- Sign a file: Signs a file with a secret key.
- Verify a file: Verifies a file for authenticity.


## Usage
- Command Line Options: The program uses the Clap library for parsing command-line arguments. The available options are as follows:


# New program below
* cargo run -- generate --name <Name of persona> --cs-id <1 through 4 CS id>
    * generates persona, generates secret and public key pair depending which cipher suite algo you want
* cargo run sign --name <Name of persona> --filename files/<name of file to hash>
    * signs a file based on persona and which file to sign
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
    1. cargo test --test main_and_commands_test
    2. cargo test --test wallet_test


## Persistence
- Persona data is stored in wallet directory in json format. 
