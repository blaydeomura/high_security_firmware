pub mod cipher_suite;
pub mod commands;
pub mod header;
pub mod wallet;

pub fn parse_pk_string(pk: &str) -> Vec<u8> {
    // Remove leading and trailing square brackets
    let pk = pk.trim_start_matches('[').trim_end_matches(']');

    // Split the string by commas to get individual number strings
    let number_strings: Vec<&str> = pk.split(", ").collect();

    // Parse each number string into u8 and collect into a Vec<u8>
    let mut byte_array: Vec<u8> = Vec::new();
    for num_str in number_strings {
        let byte = num_str.parse::<u8>().expect("Unable to parse byte");
        byte_array.push(byte);
    }
    byte_array
}
