// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

use aes_gcm::aead::Aead;
use optee_teec::{Context, Operation, Session, Uuid};
use optee_teec::{ParamNone, ParamValue, ParamType, ParamTmpRef};
use proto::{UUID, Command, Pin, Passphrase};

use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use cmac::{Cmac, Mac};
use rand::Rng;
use std::env;  

// Alias for AES-CMAC
type AesCmac = Cmac<Aes256>;

// fn hello_world(session: &mut Session) -> optee_teec::Result<()> {
//     let p0 = ParamValue::new(29, 0, ParamType::ValueInout);
//     let mut operation = Operation::new(0, p0, ParamNone, ParamNone, ParamNone);

//     println!("original value is {:?}", operation.parameters().0.a());

//     session.invoke_command(Command::IncValue as u32, &mut operation)?;
//     println!("inc value is {:?}", operation.parameters().0.a());

//     session.invoke_command(Command::DecValue as u32, &mut operation)?;
//     println!("dec value is {:?}", operation.parameters().0.a());
//     Ok(())
// }

const SEED_ID: u32 = 42;

/**
 * @brief Helps the user to use the Application.
 * @details Prints the usage of the Application.
 */
fn help() 
{
    println!("Usage: ./hello_world <command> <PIN> [<passphrase>]");
    println!("Commands:");
    println!("0 - Create seed");

    println!("Usage:");
    println!("0 - ./hello_world 0 <PIN> <passphrase>");
}

/**
 * @brief Checks the arguments of the Application.
 * @return The command, the PIN, the mnemonic and the account ID.
 */
fn check_args() -> Result<(Command, Pin, String), &'static str> 
{
    let args: Vec<String> = env::args().collect();

    if args.len() < 3
    {
        return Err("Invalid number of arguments");
    }

    let command: Command = Command::from(args[1].parse::<u32>().expect("Invalid command"));
    let pin: u32 = args[2].parse::<Pin>().expect("Invalid PIN");
    let mut passphrase: String = "".to_string();

    match command {
        Command::CreateSeed => {
            if args.len() != 4
            {
                return Err("Invalid number of arguments");
            }
            passphrase = args[3].as_str().to_string();
        }
        Command::Unknown => return Err("Invalid command"),
        _ => {}
    }
    return Ok((command, pin, passphrase));

}

fn create_seed(session: &mut Session, pin: Pin, passphrase: String) -> optee_teec::Result<()> {

    // This seed (slot) ID will be used by the Seed Vault App to bind the seed name (seed name --> seed slot ID)
    let p0_seed_id = ParamValue::new(SEED_ID, 0, ParamType::ValueInput);
    let p1_pin = ParamValue::new(pin, 0, ParamType::ValueInput);
    let p2_passphrase = ParamTmpRef::new_input(passphrase.as_bytes());
    let mut mnemonic: [u8; 512] = [0; 512];
    let p3_mnemonic = ParamTmpRef::new_output(&mut mnemonic);

    let mut operation = Operation::new(0, p0_seed_id, p1_pin, p2_passphrase, p3_mnemonic);

    // Call the Trusted Application
    match session.invoke_command(Command::CreateSeed as u32, &mut operation) {
        Ok(_) => {
            println!("Mnemonic: {}", String::from_utf8_lossy(&mnemonic));
        }
        Err(e) => {
            println!("Error: {:?}", e);
            return Ok(());
        }
    };

    Ok(())
}

fn pad_message(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut padded_message = message.to_vec();
    let pad_len = block_size - (message.len() % block_size);
    padded_message.extend(vec![pad_len as u8; pad_len]); // PKCS#7 padding
    padded_message
}

fn unpad_message(message: &[u8]) -> Vec<u8> {
    // Extract the padding length (last byte contains padding size)
    let pad_len = *message.last().unwrap() as usize;
    message[..message.len() - pad_len].to_vec()
}

fn encrypt_and_cmac(message: &str, encryption_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    if encryption_key.len() != 32 || mac_key.len() != 32 {
        return Err("Keys must be 32 bytes long");
    }

    // Generate a random initialization vector (IV)
    let mut iv = [0u8; 16];
    rand::thread_rng().fill(&mut iv);

    // Encrypt the message (AES encryption in ECB mode for simplicity)
    let cipher = Aes256::new(GenericArray::from_slice(encryption_key));
    let padded_message = pad_message(message.as_bytes(), 16); // Ensure block size
    let mut encrypted_message = Vec::new();

    for block in padded_message.chunks(16) {
        let mut block_array = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut block_array);
        encrypted_message.extend_from_slice(&block_array);
    }

    // Compute the CMAC
    let mut mac = <Cmac<Aes256> as Mac>::new_from_slice(mac_key).expect("CMAC can take key of any size");
    mac.update(&encrypted_message);
    let mac_result = mac.finalize().into_bytes().to_vec();

    Ok((encrypted_message, mac_result))
}

fn decrypt_and_verify_cmac(encrypted_message: &[u8], expected_cmac: &[u8], decryption_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<String, &'static str> {
    if decryption_key.len() != 32 || mac_key.len() != 32 {
        return Err("Keys must be 32 bytes long");
    }

    // Compute the CMAC of the encrypted message to verify it
    let mut mac = <Cmac<Aes256> as Mac>::new_from_slice(mac_key).expect("CMAC can take key of any size");
    mac.update(&encrypted_message);
    let computed_cmac = mac.finalize().into_bytes();

    // Verify CMAC
    if computed_cmac.as_slice() != expected_cmac {
        return Err("CMAC verification failed");
    }

    // Decrypt the message (AES decryption in ECB mode for simplicity)
    let cipher = Aes256::new(GenericArray::from_slice(decryption_key));
    let mut decrypted_message = Vec::new();

    for block in encrypted_message.chunks(16) {
        let mut block_array = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut block_array);
        decrypted_message.extend_from_slice(&block_array);
    }

    // Remove padding
    let decrypted_message = unpad_message(&decrypted_message);

    // Convert decrypted message to a string
    String::from_utf8(decrypted_message).map_err(|_| "Failed to convert decrypted message to UTF-8")
}

fn main() -> optee_teec::Result<()> {

    // Check the arguments
    let (command, pin, passphrase) = match check_args()
    {
        Ok((command, pin, passphrase)) => (command, pin, passphrase),
        Err(e) => {
            println!("{}", e);
            return Ok(());
        }
    };

    // Print the information
    println!("PIN: {:?}", pin);
    println!("Passphrase {:?}", passphrase);

    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    // According to the command, call the corresponding function
    match command
    {
        Command::CreateSeed => {
            create_seed(&mut session, pin, passphrase)?;
        },
        _ => {
            println!("Invalid command");
            help();
        }
    }

    // Example keys
    let encryption_key: [u8; 32] = *b"01234567890123456789012345678901";    // TODO: Use STSAFE the Host Cipher Key
    let mac_key: [u8; 32] = *b"abcdefghabcdefghabcdefghabcdefgh";           // TODO: Use STSAFE the Host MAC Key

    // Message to encrypt
    let message = "Hello, world!";

    match encrypt_and_cmac(message, &encryption_key, &mac_key) {
        Ok((encrypted_message, mac)) => {
            println!("Original Message: {}", message);
            println!("Encrypted Message: {:x?}", encrypted_message);
            println!("CMAC: {:x?}", mac);
            println!("Full CMD: {:x?}", [&encrypted_message[..], &mac[..]].concat());

            // Now decrypt and verify CMAC
            match decrypt_and_verify_cmac(&encrypted_message, &mac, &encryption_key, &mac_key) {
                Ok(decrypted_message) => println!("Decrypted Message: {}", decrypted_message),
                Err(e) => println!("Decryption or verification failed: {}", e),
            }
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("Success");

    Ok(())
}
