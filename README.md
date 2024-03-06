# Shared repo for High Security Firmware

# Encrypted Wallet Manager

## Overview
- This Rust program is a command-line tool for managing a wallet of encrypted key pairs. It provides functionality for generating, accessing, and removing key pairs securely. Keys are encrypted using AES-GCM encryption with a user-provided key.

## Features
- Generate Keys: Generate a new key pair for a person with a specific encryption key.
- Access Keys: Access a person's generated key pair with the same encryption key.
- Remove Keys: Remove an existing key pair from the wallet.
- Hash File: Calculate various cryptographic hashes for a specified file.

## Usage
- Command Line Options: The program uses the Clap library for parsing command-line arguments. The available options are as follows:

- Generate: -- generate - Generates a new key pair for a given name and encryption key.
    --name: Name of the person.
    --encryption-key: Encryption key to secure the key pair.
- Remove: -- remove - Removes an existing key pair.
    --name: Name of the person.
- Access: -- access - Accesses an existing key pair with the encryption key.
    --name: Name of the person.
    --encryption-key: Encryption key to decrypt the key pair.
    
- Sign a file: -- sign - signs a file
    -- name: Name of person and keys would like to use
    --encryption-key: Encryption key to sign
- Verify a file: -- verify - verified someone signed file
    --name: Name of person and keys would like to use
    --signature: signature given when signed

- Hash File: --hash-file - Calculate cryptographic hashes for a specified file.
    --filename: Sets the input file to calculate hash for.

## Example Usages
- Overall format:
    - cargo run -- <generate/access/remove> --name <name> --encryption-key <32 byte encryption key>
- Generate a Key:
    - cargo run -- generate --name Mallory --encryption-key "ThisIsA32ByteLongEncryptionKey00"
- Access a Key:
    - cargo run -- access --name Mallory --encryption-key "ThisIsA32ByteLongEncryptionKey00"
- Remove a Key:
    - cargo run -- remove --name Mallory

- Sign a file:
    - cargo run -- sign --name <name> --filename "<path to existing file>"
        - prompted with encryption key...
        - <32 bit encryption key that you used encrypt file>
    - example:
        - cargo run -- sign --name Mallory --filename files/file_test.txt
        - ThisIsA32ByteLongEncryptionKey00
        - output is a signature: izDIWHrJBhVX2M1ZHo+qJ2qLcfeScvfigFQW4VsTChEf+8jw0hOXCFLRPqnfGMIfHHcs2HE18htAX5amXbQdBg==
    
- Verify a file:
    - cargo run -- verify --name <name> --filename keys/<file name> --signature <signature given from sign>
        - promted to enter ecryption key.. <32 bit encryption key used when generating key>
    - example
        - cargo run -- verify --name Mallory --filename "files/file_test.txt" --signature izDIWHrJBhVX2M1ZHo+qJ2qLcfeScvfigFQW4VsTChEf+8jw0hOXCFLRPqnfGMIfHHcs2HE18htAX5amXbQdBg==
        - ThisIsA32ByteLongEncryptionKey00

- Hash a File:
    - Run "cargo build --release" to build the executable.
    - cargo run -- hash-file -- filename <filename> --algorithm <algo name>
        - cargo run -- hash-file --filename "files/file_test.txt" --algorithm "sha256"
        - cargo run -- hash-file --filename "files/file_test.txt" --algorithm "blake3"
        - cargo run -- hash-file --filename "files/file_test.txt" --algorithm "sha256"
        - cargo run -- hash-file --filename "files/file_test.txt" --algorithm "sha512"
    - openSSl Command Line Arguments:
        1. SHA-256:  openssl dgst -sha256 <filename>
        2. SHA-384:  openssl dgst -sha384 <filename>
        3. SHA-512:  openssl dgst -sha512 <filename>
        4. MD5:      openssl dgst -md5 <filename>



## Persistence
- Wallet data is stored in a JSON file named wallet.json, which contains a hashmap of names mapped to the path where the encrypted key is stored.
