use rust_omr::submitter::gen_clue;
use rust_omr::types::{Clue, OMRItem, PKClue, Payload, PublicKey, PublicParams, SecretKey};
use rust_omr; 
use utils::db::DBEntry;
// Add this line to import the utils module
use utils::{self, serialize_omr_payload};
use utils::hashing::hash_to_string;
use utils::hashing::hash_to_bytes;
use utils::aes::encrypt;
use utils::pke::EncPublicKey;


pub struct Submitter {
    public_params: PublicParams,
}

fn check_bug(bug: &[u8]) -> bool {
    // Dummy check for bug correctness
    // In a real scenario, this would involve checking a database or some other source
    true
}

impl Submitter {
    pub fn new() -> Self {
        let public_params: PublicParams = rust_omr::setup::gen_param(128, 0.1, 0.1);
        Submitter { public_params }
    }

    pub fn submit_bug(&self, pk: &EncPublicKey, clue_key: &PKClue, bug: &[u8]) -> (OMRItem, DBEntry) {
        if !check_bug(bug) {
            panic!("Bug does not meet the required criteria");
        }
        let (symmetric_key, iv) = utils::aes::generate_key_iv();
        let id_input_vec = [symmetric_key.clone(), iv.clone()].concat();
        let id_string = hash_to_string(&id_input_vec);
        let identifier = id_string.as_bytes().to_vec();
        // Ensure symmetric_key and iv are arrays of the correct size
        let symmetric_key_arr: &[u8; 32] = symmetric_key.as_slice().try_into().expect("Key must be 32 bytes");
        let iv_arr: &[u8; 16] = iv.as_slice().try_into().expect("IV must be 16 bytes");
        // Put together the symmetric key, iv, and identifier into a single payload
        let pke_input = serialize_omr_payload(symmetric_key_arr, iv_arr, identifier);

        // Encrypt the symmetric key, iv and identifier using the public key

        let pke_encryption = utils::pke::encrypt_data(&pke_input, pk);
        let payload: Payload = pke_encryption.clone();
        // Generate the clue using the public parameters, the clue key and the payload
        let clue: Clue = gen_clue(&self.public_params, clue_key.clone(), &payload);

        // Now onto the items we'll put into the DB
        // Encrypt the bug using the symmetric key and iv
        let encrypted_bug = encrypt(&bug, symmetric_key_arr, iv_arr);
        // The DB entry will contain a mapping from the "id_string" i.e. H(symmetric key || iv)
        // to the encrypted bug under this symmetric key and iv.

        let encrypted_bug_hex = utils::aes::encode_bytes_to_hex(&encrypted_bug);

        ((clue, payload), (id_string, encrypted_bug))
    }
}

