use anyhow::{Context, Result};
use clap::Parser;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use tokio::fs::remove_file;

/// Simple XOR file encryptor
#[derive(Parser)]
#[command(name = "xor_encryptor")]
#[command(about = "Encrypts a file using a key file with XOR", long_about = None)]
struct Cli {
    /// Input file to encrypt
    input: String,

    /// Key file to use for encryption
    key: String,
}

async fn xor_encrypt_file(input_path: &str, key_path: &str) -> Result<()> {
    // Open the input and key files
    let input_file = File::open(input_path).context("Failed to open input file")?;
    let mut input_reader = BufReader::new(input_file);

    let mut key_file = File::open(key_path).context("Failed to open key file")?;
    let key_file_len = key_file.metadata()?.len();
    if key_file_len == 0 {
        return Err(anyhow::anyhow!("Key file is empty"));
    }

    // Create a temporary output file
    let temp_output_path = format!("{}.tmp", input_path);
    let output_file = File::create(&temp_output_path).context("Failed to create temporary output file")?;
    let mut writer = BufWriter::new(output_file);

    // Buffers for reading
    let mut input_buffer = [0; 1024];
    let mut key_buffer = vec![0; 1024];
    let mut key_buffer_filled = 0;

    // Read the input file in chunks
    loop {
        let bytes_read = input_reader.read(&mut input_buffer).context("Failed to read input file")?;
        if bytes_read == 0 {
            break;
        }

        // Ensure key_buffer has enough bytes for the current chunk
        while key_buffer_filled < bytes_read {
            let read_amount = key_file.read(&mut key_buffer[key_buffer_filled..]).unwrap_or(0);
            if read_amount == 0 {
                // If the key file is exhausted, rewind to the start
                key_file.seek(SeekFrom::Start(0)).context("Failed to rewind key file")?;
                key_buffer_filled += key_file.read(&mut key_buffer[key_buffer_filled..]).unwrap_or(0);
            } else {
                key_buffer_filled += read_amount;
            }
        }

        // XOR each byte with the corresponding key byte
        for i in 0..bytes_read {
            input_buffer[i] ^= key_buffer[i];
        }

        // Adjust the key_buffer_filled count
        key_buffer.copy_within(bytes_read..key_buffer_filled, 0);
        key_buffer_filled -= bytes_read;

        // Write the encrypted data to the output file
        writer.write_all(&input_buffer[..bytes_read]).context("Failed to write to temporary output file")?;
    }

    // Flush the writer to ensure all data is written
    writer.flush().context("Failed to flush temporary output file")?;

    // Safely rename the encrypted file to the original file name
    drop(writer); // Ensure the writer is closed before renaming
    remove_file(input_path).await.context("Failed to delete original file")?;
    fs::rename(&temp_output_path, input_path).context("Failed to rename temporary output file")?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    xor_encrypt_file(&args.input, &args.key).await?;

    Ok(())
}

