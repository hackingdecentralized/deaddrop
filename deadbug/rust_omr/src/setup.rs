use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use serde::{Serialize, Deserialize};

// ylitchev: key file location
const KEYS_FILE_LOCATION: &str = "/tmp/funkeys.txt";

use crate::types::*;

pub fn gen_param(lambda: usize, epsilon_p: f64, epsilon_n: f64) -> PublicParams {
    PublicParams {
        lambda,
        epsilon_p,
        epsilon_n,
    }
}

#[derive(Serialize, Deserialize)]
struct KeyPair {
    sk: SecretKey,
    pk: PublicKey,
}

pub fn keygen(_pp: &PublicParams) -> (SecretKey, PublicKey) {
    if Path::new(KEYS_FILE_LOCATION).exists() {
        match read_keys_from_file() {
            Ok((sk, pk)) => {
                println!("Loaded keys from file.");
                return (sk, pk);
            }
            Err(e) => {
                println!("Failed to load keys from file, generating new ones: {}", e);
            }
        }
    }

    let sk = SecretKey {
        sk_bytes: vec![0; 32],
    };
    let pk = PublicKey {
        pk_clue: vec![1; 32],
        pk_detect: vec![1; 32],
    };

    if let Err(e) = write_keys_to_file(&sk, &pk) {
        eprintln!("Failed to write keys to file: {}", e);
    }

    (sk, pk)
}

fn write_keys_to_file(sk: &SecretKey, pk: &PublicKey) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(KEYS_FILE_LOCATION)?;

    writeln!(file, "{}", encode_sk_to_hex(sk))?;
    writeln!(file, "{}", encode_pk_clue_to_hex(&pk.pk_clue))?;
    writeln!(file, "{}", encode_pk_detect_to_hex(&pk.pk_detect))?;
    Ok(())
}

fn read_keys_from_file() -> Result<(SecretKey, PublicKey), String> {
    let mut file = File::open(KEYS_FILE_LOCATION).map_err(|e| e.to_string())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|e| e.to_string())?;

    let mut lines = contents.lines();
    let sk_hex = lines.next().ok_or("Missing secret key line")?;
    let clue_hex = lines.next().ok_or("Missing clue key line")?;
    let detect_hex = lines.next().ok_or("Missing detect key line")?;

    let sk = decode_sk_from_hex(sk_hex)?;
    let pk_clue = decode_pk_clue_from_hex(clue_hex)?;
    let pk_detect = decode_pk_detect_from_hex(detect_hex)?;

    let pk = PublicKey {
        pk_clue,
        pk_detect,
    };

    Ok((sk, pk))
}
