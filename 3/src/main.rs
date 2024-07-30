use anyhow::{Context, Result};
use clap::Parser;
use ring::pbkdf2;  // Removed unused import 'digest'
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::num::NonZeroU32;
use tokio::fs::remove_file;

/// Simple XOR file encryptor/decryptor
#[derive(Parser)]
#[command(name = "xor_encryptor")]
#[command(about = "Encrypts or decrypts a file using a key file with XOR", long_about = None)]
struct Cli {
    /// Operation mode: 'e' for encrypt, 'd' for decrypt
    #[arg(help = "Operation mode: 'e' for encrypt, 'd' for decrypt")]
    mode: String,

    /// Input file to process
    #[arg(help = "Input file to encrypt or decrypt")]
    input: String,

    /// Key file to use for encryption/decryption
    #[arg(help = "Key file to use for encryption/decryption")]
    key: String,

    /// Password for deriving salt
    #[arg(help = "Password to derive salt")]
    salt_password: String,

    /// Password for deriving nonce
    #[arg(help = "Password to derive nonce")]
    nonce_password: String,
}

fn derive_salt_and_nonce(salt_password: &str, nonce_password: &str, salt_len: usize, nonce_len: usize) -> (Vec<u8>, Vec<u8>) {
    let mut salt = vec![0u8; salt_len];
    let mut nonce = vec![0u8; nonce_len];

    // Derive salt from the salt_password
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        &[],  // No initial salt for this step
        salt_password.as_bytes(),
        &mut salt,
    );

    // Derive nonce from the nonce_password and the derived salt
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        &salt,
        nonce_password.as_bytes(),
        &mut nonce,
    );

    (salt, nonce)
}

async fn xor_process_file(input_path: &str, key_path: &str, salt_password: &str, nonce_password: &str, _decrypt: bool) -> Result<()> {
    let input_file = File::open(input_path).context("Failed to open input file")?;
    let mut input_reader = BufReader::new(input_file);

    let key_file = File::open(key_path).context("Failed to open key file")?;
    let key_file_len = key_file.metadata()?.len();
    let input_file_len = input_reader.get_ref().metadata()?.len();

    if key_file_len < input_file_len {
        return Err(anyhow::anyhow!("Key file must be at least as long as the input file"));
    }

    let mut key_reader = BufReader::new(key_file);

    let temp_output_path = format!("{}.tmp", input_path);
    let output_file = File::create(&temp_output_path).context("Failed to create temporary output file")?;
    let mut writer = BufWriter::new(output_file);

    let (_salt, nonce) = derive_salt_and_nonce(salt_password, nonce_password, 16, 12); // The salt is not used beyond this point

    let mut input_buffer = [0; 1024];
    let mut key_buffer = vec![0; 1024];

    loop {
        let bytes_read = input_reader.read(&mut input_buffer).context("Failed to read input file")?;
        if bytes_read == 0 {
            break;
        }

        let mut key_bytes_read = 0;
        while key_bytes_read < bytes_read {
            let current_read = key_reader.read(&mut key_buffer[key_bytes_read..bytes_read])
                                         .context("Failed to read key file")?;
            if current_read == 0 {
                return Err(anyhow::anyhow!("Unexpected end of key file"));
            }
            key_bytes_read += current_read;
        }

        for i in 0..bytes_read {
            input_buffer[i] ^= key_buffer[i] ^ nonce[i % nonce.len()];
        }

        writer.write_all(&input_buffer[..bytes_read]).context("Failed to write to temporary output file")?;
    }

    writer.flush().context("Failed to flush temporary output file")?;
    drop(writer);
    remove_file(input_path).await.context("Failed to delete original file")?;
    fs::rename(&temp_output_path, input_path).context("Failed to rename temporary output file")?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let decrypt = match args.mode.as_str() {
        "e" => false,
        "d" => true,
        _ => return Err(anyhow::anyhow!("Invalid mode, use 'e' for encrypt or 'd' for decrypt")),
    };

    xor_process_file(&args.input, &args.key, &args.salt_password, &args.nonce_password, decrypt).await?;

    Ok(())
}

