use deadbug_receiver::receiver::Receiver;
use rust_omr::types::{
    decode_payloads, decode_pk_detect_from_hex, encode_payloads, encode_pk_detect_to_hex, OMRItem,
    Payload,
};
use submitter::submitter::Submitter;
use utils::db::DBEntry;

pub fn main() {
    let mut receiver = Receiver::new();

    // Get the detection_key
    let detection_key = receiver.public_key.pk_detect.clone();

    let det_key_enc = encode_pk_detect_to_hex(&detection_key);

    println!("Detection Key (hex): {}", det_key_enc);

    let decoded_detection_key =
        decode_pk_detect_from_hex(&det_key_enc).expect("Failed to decode detection key from hex");

    receiver.post_info_for_submitters();

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
        decoded_detection_key.as_slice(),
        1,
    );

    // --------------------------
    // Try to decode the digest

    let encoded_digest = encode_payloads(&digest);

    println!("Encoded Digest: {}", encoded_digest);

    let digest_decoded: Vec<Payload> = decode_payloads(&encoded_digest);

    //---------------------------

    receiver.decode_digest(&digest).unwrap();

    let next_payload = receiver.get_next_decoded_payload().unwrap().unwrap();

    let (id, symmetric_key) = receiver.extract_info_from_decoded_payload(&next_payload);

    // Decrypt the bug report
    let encrypted_bug = db_entry.1;
    let encrypted_bug_hex = utils::aes::encode_bytes_to_hex(&encrypted_bug);

    let decrypted_report = receiver.decrypt_bug_report(encrypted_bug_hex.as_str(), symmetric_key);

    println!(
        "Decrypted Bug Report: {:?}",
        String::from_utf8(decrypted_report)
            .unwrap_or_else(|_| "Failed to convert decrypted report to string".to_string())
    );
    println!("Receiver main function executed successfully.");
}
