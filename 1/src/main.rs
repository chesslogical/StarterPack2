
use ring::pbkdf2;
use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
use std::fs::{File, OpenOptions};
use std::io::{Write, stdin, BufWriter};
use std::num::NonZeroU32;
use std::path::Path;
use std::collections::HashMap;

const KEY_LENGTH: usize = 32; // Length of the derived key
const OUTPUT_FILE: &str = "key.key"; // Output file name
const INFO_FILE: &str = "info.txt"; // Info file name
const KEY_SIZE_BYTES: usize = 256; // 256 bytes (2048 bits) for high entropy key
const PASSWORD_LENGTH: usize = 64; // Increased length of the generated password
const SEED_LENGTH: usize = 64; // Increased length of the generated seed
const SALT_LENGTH: usize = 32; // Increased length of the generated salt

fn generate_random_string(length: usize) -> String {
    let charset: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

fn generate_random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut bytes);
    bytes
}

fn generate_key(password: &str, seed: &[u8], salt: &[u8], length: usize) -> Vec<u8> {
    let iterations = NonZeroU32::new(100_000).expect("NonZeroU32 should not be zero");

    // Derive a key using PBKDF2 with the given salt
    let mut derived_key = [0u8; KEY_LENGTH];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password.as_bytes(),
        &mut derived_key,
    );

    // Combine the derived key with the user-provided seed to initialize the RNG
    let mut combined_seed = derived_key.to_vec();
    combined_seed.extend_from_slice(seed);
    let mut rng_seed = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        &combined_seed,
        password.as_bytes(),
        &mut rng_seed,
    );
    let mut rng = StdRng::from_seed(rng_seed);
    let mut key = Vec::with_capacity(length);

    for _ in 0..length {
        // Generate a random byte in the full range of 0-255
        let random_byte = rng.next_u32() as u8;
        key.push(random_byte);
    }

    key
}

fn count_ascii_occurrences(data: &[u8]) -> HashMap<u8, usize> {
    let mut counts = HashMap::new();
    for &byte in data {
        *counts.entry(byte).or_insert(0) += 1;
    }
    counts
}

fn write_info_file(counts: &HashMap<u8, usize>, file_path: &str, expected_bytes: usize, salts: &Vec<Vec<u8>>, seeds: &Vec<Vec<u8>>, passwords: &Vec<String>) {
    let mut file = BufWriter::new(File::create(file_path).expect("Failed to create info file"));
    for ascii in 0..=255 {
        let count = counts.get(&(ascii as u8)).unwrap_or(&0);
        writeln!(file, "{} - {}", ascii, count).expect("Failed to write to info file");
    }

    writeln!(file, "\n--- Details for Each Run ---").expect("Failed to write details");
    for (i, ((salt, seed), password)) in salts.iter().zip(seeds.iter()).zip(passwords.iter()).enumerate() {
        writeln!(file, "Run {}: ", i + 1).expect("Failed to write run details");
        writeln!(file, "Password: {}", password).expect("Failed to write password");
        writeln!(file, "Seed: {:?}", seed).expect("Failed to write seed");
        writeln!(file, "Salt: {:?}", salt).expect("Failed to write salt");
    }

    // Analysis of randomness
    let unique_characters = counts.len();
    let actual_count: usize = counts.values().sum();
    let entropy = calculate_entropy(&counts, actual_count);

    writeln!(file, "\n--- Analysis ---").expect("Failed to write analysis");
    writeln!(file, "Total unique characters: {}", unique_characters).expect("Failed to write analysis");
    writeln!(file, "Expected byte count: {}", expected_bytes).expect("Failed to write analysis");
    writeln!(file, "Actual byte count: {}", actual_count).expect("Failed to write analysis");
    writeln!(file, "Entropy: {:.2} bits per byte (0 to 8, where 8 is best)", entropy).expect("Failed to write analysis");

    // Check if the total number of bytes matches the expected value
    if actual_count == expected_bytes {
        writeln!(file, "The total number of characters matches the expected byte count.").expect("Failed to write analysis");
    } else {
        writeln!(file, "Discrepancy in the total number of characters vs expected bytes.").expect("Failed to write analysis");
    }

    if unique_characters < 256 {
        writeln!(file, "Not all ASCII characters are present. This is expected in small samples but increases with sample size.").expect("Failed to write analysis");
    }

    writeln!(file, "Randomness appears normal.").expect("Failed to write analysis");
}

fn calculate_entropy(counts: &HashMap<u8, usize>, total: usize) -> f64 {
    let mut entropy = 0.0;
    for &count in counts.values() {
        if count > 0 {
            let probability = count as f64 / total as f64;
            entropy -= probability * probability.log2();
        }
    }
    entropy
}

fn main() {
    // Check if the key file already exists
    if Path::new(OUTPUT_FILE).exists() {
        eprintln!("Error: {} already exists. Exiting.", OUTPUT_FILE);
        std::process::exit(1);
    }

    let mut runs_str = String::new();
    println!("Enter the number of runs (each run generates a new segment of the key):");
    stdin().read_line(&mut runs_str).expect("Failed to read number of runs");
    let runs: usize = runs_str.trim().parse().expect("Invalid number");

    let mut generate_report_str = String::new();
    println!("Generate report? (y/n):\nNote: The report will be saved to info.txt and will overwrite any existing file with the same name.");
    stdin().read_line(&mut generate_report_str).expect("Failed to read input");
    let generate_report = generate_report_str.trim().to_lowercase() == "y";

    let mut total_key_data = Vec::new();
    let mut salts_used = Vec::new();
    let mut seeds_used = Vec::new();
    let mut passwords_used = Vec::new();

    for _ in 0..runs {
        // Generate random password, seed, and salt
        let password = generate_random_string(PASSWORD_LENGTH);
        let seed = generate_random_bytes(SEED_LENGTH);
        let salt = generate_random_bytes(SALT_LENGTH);
        salts_used.push(salt.clone());
        seeds_used.push(seed.clone());
        passwords_used.push(password.clone());

        let key = generate_key(&password, &seed, &salt, KEY_SIZE_BYTES);
        total_key_data.extend(&key);

        // Append the key to the output file
        let mut file = OpenOptions::new().append(true).create(true).open(OUTPUT_FILE).expect("Failed to create or open output file");
        if let Err(e) = file.write_all(&key) {
            eprintln!("Error writing to file: {}", e);
        }
    }

    if generate_report {
        let ascii_counts = count_ascii_occurrences(&total_key_data);
        let expected_bytes = KEY_SIZE_BYTES * runs;
        write_info_file(&ascii_counts, INFO_FILE, expected_bytes, &salts_used, &seeds_used, &passwords_used);
        println!("Report generated and saved to {}", INFO_FILE);
    }

    println!("Keys generated and saved to {}", OUTPUT_FILE);
}
