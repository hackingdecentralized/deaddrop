use deadbug_receiver::receiver::Receiver;
// ylitchev: for command line inputs
use dialoguer::{theme::ColorfulTheme, Input, Select};
// ylitchev: to process payloads
use rust_omr::types::{decode_payloads, encode_pk_detect_to_hex, Payload};

use log::{info, warn, error, debug, trace};

fn main() {

    env_logger::init();

    // Create an instance of the receiver
    let mut receiver = Receiver::new();

    //At start up we create the receiver and all the info
    // and we print the info for the frontend

    // Then we have a menu with multiple options:

    // 0. Print Receiver internal state

    // 1. Get detection key to request the digest (compress digest of pertinent messages, in our case encrypted symmetric keys for retrieving later bug reports)

    // 2. Decode the digest to get the info to retrieve the bug reports (index to query the database)

    // 3. Give the id for the file to retrieve and parse an HEX string of the CXTX to decrypt the bug report to get the bug report

    debug!("Receiver is running...");

    // let detection_key: PKDetect;

    loop {
        // Menu items shown to the user
        let menu_items = [
            "1. Print Receiver Info",
            "2. Get detection key",
            "3. Decode digest",
            "4. Decrypt bug report",
            "5. Exit",
        ];

        // Arrow-key, highlighted selection
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose an option (↑/↓ then Enter)")
            .items(&menu_items)
            .default(0)
            .interact()
            .expect("terminal interaction failed");

        // Act on the chosen item
        match selection {
            0 => handle_print(&mut receiver),
            1 => handle_detection_key(&mut receiver),
            2 => handle_decode_digest(&mut receiver),
            3 => handle_process_id(&mut receiver),
            4 => {
                info!("Exiting. Goodbye!");
                break;
            }
            _ => unreachable!(), // `Select` guarantees 0-3 only
        }
    }
}

// ylitchev: print out the stored detection key
fn handle_detection_key(receiver: &mut Receiver) {
    info!("Option 1 selected: Get detection key");

    let temp = receiver.public_key.pk_detect.clone();
    let pk_detect_hex = encode_pk_detect_to_hex(&temp);
    info!("Detection key set to {:?}", pk_detect_hex);
    
}

fn handle_print(receiver: &mut Receiver) {
    info!("Option 0 selected: Print Receiver Info");

    receiver.post_info_for_submitters();
}

// ylitchev: given an input digest, decode it by calling the
//           appropriate function in reciever.rs
fn handle_decode_digest(receiver: &mut Receiver) {
    let digest_input: String = Input::new()
        .with_prompt("Paste digest string (press Enter to leave empty)")
        .allow_empty(true)
        .interact_text()
        .expect("failed to read digest");

    // Convert to Vec<Payload> (Vec<Vec<u8>>).  Replace this stub with real parsing logic.

    // Transformation of a (String) into a (Vec<Vec<u8>>)
    // let bytes_vec: Vec<u8> = digest_input.into_bytes();
    // let mut vec_of_vec: Vec<Vec<u8>> = Vec::new();
    // vec_of_vec.push(bytes_vec);

    // decode the digest input
    let decoded_digest = decode_payloads(digest_input.as_str());

    // Decode the digest by calling the appropriate function from receiver.rs
    receiver.decode_digest(&decoded_digest);
}

// ylitchev: Pop the most recent payload from the queue, process it
//           in order to receive an id and symmetric key. Wait for a
//           ciphertext, when given, decrypt it
fn handle_process_id(receiver: &mut Receiver) {
    // Get first element from queue
    let popped_element = receiver.get_next_decoded_payload();
    match popped_element {
        Ok(element) => {
            if element.is_some() {
                // There is an element, unwrap and parse it
                let payload = element.unwrap();

                let (id, symmetric_key) = receiver.extract_info_from_decoded_payload(&payload);

                info!("We have an id=[{id}]");

                // Request a ciphertext from user input
                let ciphertext: String = Input::new()
                    .with_prompt("Enter the ciphertext and press Enter")
                    .interact_text()
                    .expect("failed to read line");

                info!("You typed: {ciphertext}\n");

                // Decode the ciphertext, get the plaintext and print it
                let plaintext = receiver.decrypt_bug_report(&ciphertext, symmetric_key);

                info!("Resulting plaintext: {:?}", plaintext);
            } else {
                warn!("Nothing was popped from queue!");
            }
        }
        Err(e) => {
            warn!("Error popping element: {}", e);
            return; // Exit if there's an error
        }
    }
}

// ylitchev: Dummy template function to handle command-line inputs
/// Helper: prompt for arbitrary user input, then echo it with a custom banner.
fn handle_option(banner: &str) {
    println!("\n{banner}");
    let input: String = Input::new()
        .with_prompt("Enter anything and press Enter")
        .interact_text()
        .expect("failed to read line");

    println!("You typed: {input}\n");
}
