use std::collections::VecDeque;

use rust_omr::receiver::decode;
use rust_omr::setup::{gen_param, keygen};
use rust_omr::types::{encode_pk_clue_to_hex, Payload, PublicKey, PublicParams, SecretKey};

use crate::types::{BugInfo, BugMetadata, BugStatus, EncKeys, ReceiverError};

use utils::deserialize_omr_payload;

use log::{info, warn, error, debug, trace};

pub struct Receiver {
    // Fields for the receiver
    pub public_params: PublicParams,
    pub public_key: PublicKey,
    secret_key: SecretKey,
    bug_info: BugInfo,
    pub enc_keys: EncKeys,
    decoded_paylods_queue: VecDeque<Payload>, // A queue to store retrieved info not yet fetched from the DB
}

impl Receiver {
    // Constructor for the receiver
    pub fn new() -> Self {
        let pp: PublicParams = gen_param(128, 0.1, 0.1);
        let (sk, pk) = keygen(&pp);

        let bug_info = BugInfo {
            addr: "<contract_address>".to_string(),
            rules: "<invariants of the bug>".to_string(),
        };

        let enc_keys = EncKeys::key_gen();

        let decoded_payloads = VecDeque::new();

        Receiver {
            public_params: gen_param(128, 0.1, 0.1),
            public_key: pk,
            secret_key: sk,
            bug_info,
            enc_keys,
            decoded_paylods_queue: decoded_payloads,
        }
    }

    pub fn post_info_for_submitters(&self) {
        // Logic to post the bug information for submitters

        info!("Bug Address: {}", self.bug_info.addr);
        info!("Bug Rules: {}", self.bug_info.rules);

        let clue_key = self.public_key.pk_clue.clone();
        let enc_key = self.enc_keys.pk_enc.clone();

        info!("Encryption Key: {:?}", enc_key);
        info!("Clue Key: {}", encode_pk_clue_to_hex(&clue_key));
    }

    pub fn decode_digest(&mut self, digest: &Vec<Payload>) -> Result<(), ReceiverError> {
        let dec_payload = decode(&self.public_params, digest.clone(), &self.secret_key);

        match dec_payload {
            rust_omr::types::DecodeResult::PayloadList(decoded) => {
                //use a queue to do this
                for payload in decoded.iter() {
                    self.decoded_paylods_queue.push_back(payload.to_vec());
                }

                info!("Decoded Payloads added to the internal queue!");
                Ok(())
            }
            _ => {
                info!("Decoding failed or overflow occurred.");
                return Err(ReceiverError(
                    "Decoding failed or overflow occurred.".to_string(),
                ));
            }
        }
    }

    // Method to extact one item from the queue
    // This will give the id to fetch the file

    pub fn get_next_decoded_payload(&mut self) -> Result<Option<BugMetadata>, ReceiverError> {
        if !self.decoded_paylods_queue.is_empty() {
            let decoded_payload = self.decoded_paylods_queue.pop_front();

            // Deserialize the payload to extract id and symmetric key and the identifier
            if let Some(payload) = &decoded_payload {
                // Decrypt the payload
                let decrypted_payload = self.enc_keys.decrypt(payload);
                // Extracting the key, iv and identifier from the decrypted payload
                let result = deserialize_omr_payload(decrypted_payload.as_slice());
                match result {
                    Ok((key, iv, identifier)) => {
                        // identifier needs to be converted to a string

                        let identifier = String::from_utf8(identifier);

                        if identifier.is_err() {
                            error!("Error converting identifier to string: {}", identifier.err().unwrap());
                            return Err(ReceiverError("Failed to convert identifier to string".to_string()));
                        }

                        let identifier = identifier.unwrap();
                        info!("Extracted ID: {}", identifier);

                        return Ok(Some(BugMetadata {
                            bug_id: identifier,
                            symmetric_key: (key, iv), // Tuple containing symmetric key and IV
                            encrypted_bug: String::new(), // Placeholder for encrypted bug in hex format
                            decrypted_bug: String::new(), // Placeholder for decrypted bug content
                            status: BugStatus::Pending,   // Initial status
                        }));
                    }
                    Err(e) => {
                        error!("Error deserializing payload: {}", e);
                        return Err(ReceiverError(format!("Failed to deserialize payload: {}", e)));
                    }
                }
            } else {
                warn!("No payloads available in the queue.");
                return Ok(None);
            }
        }else {
            warn!("No decoded payloads available.");
            return Ok(None);
        }
    }

    // Method to extract id and symmetric key from the decoded payload (popped from the queue by previous function)
    pub fn extract_info_from_decoded_payload(
        &self,
        payload: &BugMetadata,
    ) -> (String, (Vec<u8>, Vec<u8>)) {
        // Extract the id and symmetric key from the BugMetadata

        // TODO: perhaps to remove
        let id = payload.bug_id.clone();
        let symmetric_key = payload.symmetric_key.clone();

        (id, symmetric_key)
    }

    pub fn decrypt_bug_report(
        &self,
        enc_hex_file: &str,
        symmetric_key: (Vec<u8>, Vec<u8>),
    ) -> Vec<u8> {
        // Logic to decrypt the bug report using the symmetric key
        // For now, we just return a dummy decrypted report

        let (key, iv) = symmetric_key;

        // the ciphertext is in hex format
        let ciphertext = utils::aes::decode_hex_to_bytes(enc_hex_file);

        let decrypted_report = utils::aes::decrypt(&ciphertext, &key.as_slice(), &iv.as_slice());

        // Convert decrypted bytes to string and return
        // utils::aes::encode_bytes_to_hex(&decrypted_report)

        decrypted_report
    }
}

#[cfg(test)]
mod tests {
    use rust_omr::types::{decode_payloads, encode_payloads, OMRItem};
    use submitter::submitter::Submitter;
    use utils::db::DBEntry;

    use super::*;

    #[test]
    fn test_post_info_for_submitters() {
        let receiver = Receiver::new();
        receiver.post_info_for_submitters();
    }

    #[test]
    fn test_decode_digest() {
        let mut receiver = Receiver::new();

        // Get the detection_key
        let detection_key = receiver.public_key.pk_detect.clone();

        // Code from other modules
        // -------------------------------

        // Create a Submitter instance to generate the data for the BB
        let submitter = Submitter::new();
        let bug = b"Test bug report".to_vec();
        let (omr_item, db_entry): (OMRItem, DBEntry) = submitter.submit_bug(
            &receiver.enc_keys.pk_enc,
            &receiver.public_key.pk_clue,
            &bug,
        );

        // Create the bulletin board with the omr_item
        let bulletin_board = vec![omr_item];
        // Create the digest from the detector
        let digest = rust_omr::detector::detect(
            &receiver.public_params,
            &bulletin_board,
            detection_key.as_slice(),
            1,
        );

        // --------------------------

        let result = receiver.decode_digest(&digest);
        assert!(result.is_ok());
        assert!(!receiver.decoded_paylods_queue.is_empty());
    }

    #[test]
    fn test_get_next_decoded_payload() {
        let mut receiver = Receiver::new();

        // Get the detection_key
        let detection_key = receiver.public_key.pk_detect.clone();

        // Code from other modules
        // -------------------------------

        // Create a Submitter instance to generate the data for the BB
        let submitter = Submitter::new();
        let bug = b"Test bug report".to_vec();
        let (omr_item, db_entry): (OMRItem, DBEntry) = submitter.submit_bug(
            &receiver.enc_keys.pk_enc,
            &receiver.public_key.pk_clue,
            &bug,
        );

        // Create the bulletin board with the omr_item
        let bulletin_board = vec![omr_item];
        // Create the digest from the detector
        let digest = rust_omr::detector::detect(
            &receiver.public_params,
            &bulletin_board,
            detection_key.as_slice(),
            1,
        );

        // --------------------------

        receiver.decode_digest(&digest).unwrap();

        let next_payload = receiver.get_next_decoded_payload().unwrap();

        assert!(next_payload.is_some());

        // Check BugMetadata fields
        if let Some(metadata) = next_payload {
            assert!(!metadata.bug_id.is_empty());
            assert!(!metadata.symmetric_key.0.is_empty());
            assert!(!metadata.symmetric_key.1.is_empty());
            assert_eq!(metadata.status, BugStatus::Pending);
        } else {
            panic!("No payloads available in the queue.");
        }
    }

    #[test]
    fn test_decrypt_bug_report() {
        let mut receiver = Receiver::new();

        // Get the detection_key
        let detection_key = receiver.public_key.pk_detect.clone();

        // Code from other modules
        // -------------------------------

        // Create a Submitter instance to generate the data for the BB
        let submitter = Submitter::new();
        let bug = b"Test bug report".to_vec();
        let (omr_item, db_entry): (OMRItem, DBEntry) = submitter.submit_bug(
            &receiver.enc_keys.pk_enc,
            &receiver.public_key.pk_clue,
            &bug,
        );

        // Create the bulletin board with the omr_item
        let bulletin_board = vec![omr_item];
        // Create the digest from the detector
        let digest = rust_omr::detector::detect(
            &receiver.public_params,
            &bulletin_board,
            detection_key.as_slice(),
            1,
        );

        // --------------------------
        // Try to decode the digest

        let encoded_digest = encode_payloads(&digest);

        let digest_decoded: Vec<Payload> = decode_payloads(&encoded_digest);

        assert_eq!(digest, digest_decoded);

        //---------------------------

        receiver.decode_digest(&digest).unwrap();

        let next_payload = receiver.get_next_decoded_payload().unwrap().unwrap();

        let (id, symmetric_key) = receiver.extract_info_from_decoded_payload(&next_payload);

        assert!(!id.is_empty());

        // Decrypt the bug report
        let encrypted_bug = db_entry.1;
        let encrypted_bug_hex = utils::aes::encode_bytes_to_hex(&encrypted_bug);

        let decrypted_report =
            receiver.decrypt_bug_report(encrypted_bug_hex.as_str(), symmetric_key);

        assert_eq!(decrypted_report, bug)
    }
}
