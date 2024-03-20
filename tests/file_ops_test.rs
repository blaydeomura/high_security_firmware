// #[cfg(test)]
// mod tests {
//     use super::*;
//     use std::fs::{self, File};
//     use std::io::Write;

//     // Import hash_file function from your file_ops module
//     use rust_cli::file_ops::hash_file;

//     #[test]
// fn test_hash_file_blake3() {
//     let filename = "file_test.txt";
//     let expected_hash = "92b73e3644c76d24adc54ff5a385fc7bf64def1a795dbcdbee3c729b148a91e1"; // Expected hash for the given content
//     let content = "This is a hashing test.\n";

//     create_test_file(filename, content);

//     if let Ok(hash) = hash_file(filename, "blake3") {
//         assert_eq!(hash, expected_hash);
//     } else {
//         panic!("Failed to hash file using BLAKE3 algorithm.");
//     }

//     fs::remove_file(filename).unwrap();
// }

// #[test]
// fn test_hash_file_sha256() {
//     let filename = "file_test.txt";
//     let expected_hash = "1d5e549a6da0a996b931324ad741d1a5724f5151f098e78c6378c5b6359be597"; // Expected hash for the given content
//     let content = "This is a hashing test.\n";

//     create_test_file(filename, content);

//     if let Ok(hash) = hash_file(filename, "sha256") {
//         assert_eq!(hash, expected_hash);
//     } else {
//         panic!("Failed to hash file using SHA-256 algorithm.");
//     }

//     fs::remove_file(filename).unwrap();
// }

// // Uncomment and add tests for other hash algorithms as needed

// // #[test]
// // fn test_hash_file_sha384() {
// //     let filename = "file_test.txt";
// //     let expected_hash = "7b39d81d5b97c243951b8db0a83389da98a40ff5eb81e4355aa0c2a10f83473e554245b375f82b6990b4e65cf8b39396"; // Expected hash for the given content
// //     let content = "This is a hashing test.\n";

// //     create_test_file(filename, content);

// //     if let Ok(hash) = hash_file(filename, "sha384") {
// //         assert_eq!(hash, expected_hash);
// //     } else {
// //         panic!("Failed to hash file using SHA-384 algorithm.");
// //     }

// //     fs::remove_file(filename).unwrap();
// // }

// #[test]
// fn test_hash_file_sha512() {
//     let filename = "file_test.txt";
//     let expected_hash = "e0d46ba9a98ff4ed496587b174447ef8c64d1d4e6a1fd0031bc0a1059db1ad5cea0ea922f86990f80309acc9a9abcf8098dfdf4849f15275906a25ae62e40c44"; // Expected hash for the given content
//     let content = "This is a hashing test.\n";

//     create_test_file(filename, content);

//     if let Ok(hash) = hash_file(filename, "sha512") {
//         assert_eq!(hash, expected_hash);
//     } else {
//         panic!("Failed to hash file using SHA-512 algorithm.");
//     }

//     fs::remove_file(filename).unwrap();
// }
