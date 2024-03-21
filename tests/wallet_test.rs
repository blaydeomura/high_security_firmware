use rust_cli::wallet::Wallet;
use rust_cli::persona::Persona;
use std::time::{Instant};

// Define a function to generate a persona and measure the time taken
fn generate_persona_benchmark() -> (usize, u128) {
    let start_time = Instant::now();

    // Perform the operation you want to benchmark (e.g., generate a persona)
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);
    wallet.save_persona(test_persona.clone()).unwrap();

    let end_time = start_time.elapsed().as_nanos();

    // Return the size of the public key and the elapsed time
    (test_persona.get_pk().as_ref().len(), end_time)
}

// Define a function to remove a persona and measure the time taken
fn remove_persona_benchmark() -> u128 {
    let start_time = Instant::now();

    // Perform the operation you want to benchmark (e.g., remove a persona)
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);
    wallet.save_persona(test_persona.clone()).unwrap();
    wallet.remove_persona("test_persona").unwrap();

    let end_time = start_time.elapsed().as_nanos();

    // Return the elapsed time
    end_time
}

#[test]
fn test_performance() {
    let (pk_size, gen_time) = generate_persona_benchmark();
    let rmv_time = remove_persona_benchmark();

    // Convert nanoseconds to milliseconds
    let gen_time_ms = gen_time as f64 / 1_000_000.0;
    let rmv_time_ms = rmv_time as f64 / 1_000_000.0;

    // Print the results in a table format
    println!("Performance Test Results:");
    println!("Operation\t\tSize of Public Key\tTime (ms)");
    println!("---------------------------------------------------");
    println!("Generate Persona\t{}\t\t\t{:.2}", pk_size, gen_time_ms);
    println!("Remove Persona\t\t\t\t\t{:.2}", rmv_time_ms);
}

#[test]
fn test_generate_persona() {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);

    assert!(wallet.save_persona(test_persona.clone()).is_ok());
    assert_eq!(wallet.keys.len(), 1);

    // Check if the persona exists in the wallet
    assert!(match wallet.get_persona("test_persona") {
        Some(persona) => *persona == test_persona,
        None => false,
    });
}

#[test]
fn test_remove_persona() {
    let mut wallet = Wallet::new();
    let test_persona = Persona::new("test_persona".to_string(), 1);

    wallet.save_persona(test_persona.clone()).unwrap();
    assert_eq!(wallet.keys.len(), 1);

    // Remove the persona from the wallet
    assert!(wallet.remove_persona("test_persona").is_ok());

    // Check if the persona has been removed from the wallet
    assert_eq!(wallet.get_persona("test_persona"), None);
}
