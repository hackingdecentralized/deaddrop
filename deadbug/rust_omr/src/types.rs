use bincode;
use hex;


pub type Payload = Vec<u8>; // x ∈ {0,1}^P

pub fn encode_payloads(payloads: &Vec<Vec<u8>>) -> String {
    let serialized = bincode::serialize(payloads).expect("Failed to serialize");
    hex::encode(serialized)
}

pub fn decode_payloads(hex_str: &str) -> Vec<Vec<u8>> {
    let decoded_bytes = hex::decode(hex_str).expect("Invalid hex");
    bincode::deserialize(&decoded_bytes).expect("Failed to deserialize")
}

pub type Clue = Vec<u8>;
pub type OMRItem = (Clue, Payload); // (clue, payload)
pub type BulletinBoard = Vec<OMRItem>;


pub type PKDetect = Vec<u8>; // Public key for detection
pub type PKClue = Vec<u8>; // Public key for clue generation

// #[derive(Clone)]
// pub struct PublicParams {
//     pub lambda: usize,
//     pub epsilon_p: f64,
//     pub epsilon_n: f64,
// }

// #[derive(Clone)]
// pub struct PublicKey {
//     pub pk_clue: PKClue,
//     pub pk_detect: PKDetect,
// }
    
pub fn encode_pk_detect_to_hex(pk_detect: &PKDetect) -> String {
    hex::encode(pk_detect)
}
pub fn decode_pk_detect_from_hex(hex_str: &str) -> Result<PKDetect, String> {
    hex::decode(hex_str).map_err(|e| e.to_string())
}
pub fn encode_pk_clue_to_hex(pk_clue: &PKClue) -> String {
    hex::encode(pk_clue)
}
pub fn decode_pk_clue_from_hex(hex_str: &str) -> Result<PKClue, String> {
    hex::decode(hex_str).map_err(|e| e.to_string())
}

// ylitchev: encode and decode sk to/from hex as is done with the public keys
pub fn encode_sk_to_hex(sk: &SecretKey) -> String {
    hex::encode(&sk.sk_bytes)
}

pub fn decode_sk_from_hex(hex_str: &str) -> Result<SecretKey, String> {
    hex::decode(hex_str)
        .map(|bytes| SecretKey { sk_bytes: bytes })
        .map_err(|e| e.to_string())
}


// #[derive(Clone)]
// pub struct SecretKey {
//     pub sk_bytes: Vec<u8>,
// }

pub enum DecodeResult {
    PayloadList(Vec<Payload>),
    Overflow,
}


// ylitchev: extra

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct SecretKey {
    pub sk_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKey {
    pub pk_clue: Vec<u8>,
    pub pk_detect: Vec<u8>,
}

pub struct PublicParams {
    pub lambda: usize,
    pub epsilon_p: f64,
    pub epsilon_n: f64,
}


