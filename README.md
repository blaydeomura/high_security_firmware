# Encrypted Wallet Manager

## Overview
- This Rust program is a command-line tool for managing a wallet of ciphersuite objects. A ciphersuite object consists of a name and a key pair generated using quantum and or eliptic curve algorithms. Users can generate and remove ciphersuites as well as sign and verify files using the key pairs stored.

## Problem Statement
- According to Microsoft and Google, 70% of security vulnerabilities are due to memory safety issues. Micron currently writes a large amount of their code in C, which is not a memory safe language. In order to stay up to date with current security practices, it is important to develop software that is both performant and memory safe.
Cryptographic algorithms are integral to the security of our communications today. The algorithms that are currently in use are only secure as long as quantum computers do not exist. The NIST predicts that current algorithms could be broken as soon as 2030, so it is important to transition to using quantum safe cryptography for our communications.

## Solution
- By writing the code base entirely in Rust, we accomplish the goals of both memory safety and high performance. Many languages offer memory safety, but lack in speed and performance compared to C. Due to the compiler and the borrow checker, Rust is able to be memory safe by default without sacrificing any of the speed that is imperative for high performance applications.
In order to make our tool future proof, we used quantum safe algorithms for key generation, signing, and verification. Over the past few years, the NIST has been soliciting proposals to determine a standard for quantum safe cryptographic algorithms. In 2022, Dilithium and Falcon were two of the algorithms selected. We used the Open Quantum Safe implementation of these algorithms to ensure our CLI tool is up to date with the current security standards.

## Features
- Generate: Generate a new key pair using the specified algorithm.
- Remove: Remove an existing key pair from the wallet.
- Sign: Signs a file with a secret key.
- Verify: Verifies a file using public key and signature provided.
- Peer-to-Peer verify: Verify a signed file from a different machine


## Usage
The program uses the Clap library for parsing command-line arguments. All subcommands support both long and short versions. The available options are as follows:

* View combination of algorithms in each cipher suite
```
./qs_wallet algorithms
```

* Generate a new ciphersuite with the specified algorithms
```
./qs_wallet generate -n <name> -c <cs id> -w .wallet
```

* Sign a file using the specified cipher suite object
```
./qs_wallet sign -n <name> -f <file to sign> -o <signed file output name> -w .wallet
```

* Verify a file based on signer and header file
```
./qs_wallet verify -n <name> -f <signed data file> -w .wallet
```

* Remove a cipher suite object from wallet
```
./qs_wallet remove -n <name> -w .wallet
```

## To Build and Run an Executable
```
cargo build --release
```
* Copy the path to executable and place in a target directory
```
cp <src executable path>/qs_wallet <destination directory for executable>
```

* From here, you can run the commands below

## Example
```
./qs_wallet generate -n bob -c 1 -w .wallet
./qs_wallet generate -n mallory -c 2 -w .wallet
./qs_wallet generate -n dude -c 3 -w .wallet
./qs_wallet generate -n alice -c 4 -w .wallet
./qs_wallet generate -n shiv -c 5 -w .wallet
```
* You will expect the output "Ciphersuite generated successfully"

```
./qs_wallet sign -n bob -f README.md -o bob_test_sig -w .wallet
./qs_wallet sign -n mallory -f Cargo.lock -o mallory_test_sig -w .wallet
./qs_wallet sign -n dude -f Cargo.toml -o dude_test_sig -w .wallet
./qs_wallet sign -n alice -f src/commands.rs -o alice_test_sig -w .wallet
./qs_wallet sign -n shiv -f src/header.rs -o shiv_test_sig -w .wallet
```
* You will expect the output "Ciphersuite signed successfully"
* Note that your files can be anywhere, but you must specify the path location 

```
./qs_wallet verify -n bob -f bob_test_sig -w .wallet
./qs_wallet verify -n mallory -f mallory_test_sig -w .wallet
./qs_wallet verify -n dude -f dude_test_sig -w .wallet
./qs_wallet verify -n alice -f alice_test_sig -w .wallet
./qs_wallet verify -n shiv -f shiv_test_sig -w .wallet
```
* You will expect the output "Ciphersuite verified successfully"

```
./qs_wallet remove -n bob -w .wallet
./qs_wallet remove -n mallory -w .wallet
./qs_wallet remove -n dude -w .wallet
./qs_wallet remove -n alice -w .wallet
./qs_wallet remove -n shiv -w .wallet
```
* You will expect the output "Ciphersuite removed successfully"
* Note: You will want to remove your signed output file as well if you remove the corresponding name from wallet

# How to Peer-to-Peer Verify
## Print public key (on machine that signed the file)
```
./qs_wallet print-keys -w .wallet
```
* Copy the numbers including the brackets ie "[12 23 45 ... example key numbers here]"
* If you need to verify on a different machine, send the copied public key via email or another way
* On the other machine, run the command below with the sent public key...

## Peer Verify (on second machine)
* Note: must the both the copied public key string + signed file to verify
```
./qs_wallet peer-verify --pk "<Insert key and include enclosing brackets>" --file <file to verify>
```

# Testing Core Functionality
```
cargo test --test official_tests -- --show-output  
``` 
* Note that this cannot be run in executable but rather via using cargo

# Persistence
- Cipher suite object data is stored in a .wallet file in cbor (concise binary) format. 
