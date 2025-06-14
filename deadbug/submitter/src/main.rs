use std::env;
use std::fs::File;
use std::io::{self, Read, Write};
use rust_omr::types::PublicParams;
use submitter::submitter::Submitter;
use submitter::submitter::*;
use utils::pke::pk_from_string;
use hex;
// use crate::check_bug_impl; // Uncomment and fix this if check_bug_impl exists elsewhere
fn read_contract_addr(file_path: &str) -> io::Result<String> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents.trim().to_string())
}

fn read_block_num(file_path: &str) -> io::Result<u32> {
    let mut file = File::open(file_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    contents
        .trim()
        .parse::<u32>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn main() {
    // Get everthing you need for the bug check
    let bug_file = "bug/bug_report.sol";
    // let block_num_file = "test/block_num.txt";
    // let test_file = "test/test_example.sol";
    // let contract_addr_file = "test/contract_addr.txt";

    // let block_num = read_block_num(block_num_file).unwrap();
    // let contract_addr = read_contract_addr(contract_addr_file).unwrap();
    // // Check the correctness of the bug
    // let check = check_bug_impl(&contract_addr, block_num, &bug_file, &test_file);

    // assert!(check, "Bug check failed");

    // Now read the bug file, encryption stuff and submit the bug

    let mut bug_file = File::open(bug_file).unwrap();
    let mut buffer = Vec::new();
    bug_file.read_to_end(&mut buffer).unwrap();
    let bug = buffer.as_slice();

    let submitter = Submitter::new();

    // let enc_pk_file = "test/enc_pk.txt";
    // let enc_pk = File::open(enc_pk_file).expect("Failed to open enc_pk file");
    let enc_pk_str = "age10x4whtpda5dqcmty2m4pza02e6y9lxx8zqz7duelrjkmxmvn8emsnc2ydd";
    let enc_pk = pk_from_string(enc_pk_str);
    let clue_key_str = "1c0fda1929df4033c3caf80ce1504cc7e9349f9c56661d57eaabf36c29d7c54e";
    let clue_key = hex::decode(clue_key_str).expect("Failed to decode clue key from hex");
    // let clue_key_file = "test/clue_key.txt";
    // let clue_key = File::open(clue_key_file).expect("Failed to open clue_key file");

        let (omr_item, db_entry) = submitter.submit_bug(
            &enc_pk,
            &clue_key,
            bug
        );
        println!("Bug submitted successfully");

    let data_to_submit = utils::db::data_to_submitted_data(omr_item, db_entry, None);
    let json_file_path = "../../submitted_data.json";
    utils::db::write_data_to_json_file(&data_to_submit, json_file_path).expect("Failed to write data to JSON file");
}
