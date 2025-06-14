use std::error::Error;
use utils::pke::*;

#[derive(Debug)]
pub struct ReceiverError(pub String);

impl std::fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReceiverError: {}", self.0)
    }
}

impl Error for ReceiverError {}

#[derive(Clone, Debug)]
pub struct BugInfo {
    pub addr: String,
    pub rules: String,
}

// Decide which scheme should we use
#[derive(Clone)]
pub struct EncKeys {
    pub pk_enc: EncPublicKey, // Public key for encryption
    sk_enc: EncPrivateKey,    // Secret key for encryption
}

impl EncKeys {
    pub fn key_gen() -> Self {
        // Generate keys for encryption
        let (sk, pk) = key_gen();

        let pk_enc = pk; // Placeholder for public key
        let sk_enc = sk; // Placeholder for secret key

        // Call keygen from utils
        EncKeys { pk_enc, sk_enc }
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Vec<u8> {
        // Decrypt the data using the secret key
        let decrypted_data = decrypt_data(encrypted_data, &self.sk_enc);
        decrypted_data
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum BugStatus {
    Pending,   // Bug is pending review
    Retrieved, // Bug has been retrieved from the database
    Decrypted, // Bug has been decrypted
    Saved,     // Bug has been saved on file
}
pub struct BugMetadata {
    pub bug_id: String,                    // Unique identifier for the bug
    pub symmetric_key: (Vec<u8>, Vec<u8>), // Symmetric key used for encryption
    pub encrypted_bug: String,             // Cxtx in hex format
    pub decrypted_bug: String,             // Decrypted bug content or file name
    pub status: BugStatus,                 // Status of the bug
}
