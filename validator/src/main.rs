use std::fs::File;
use std::io::{self, Read};
use std::error::Error;
use std::process::Command;

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

fn gen_attestation() -> Result<String, Box<dyn Error>> {
    // Spawn `python3 gen_attestation.py`
    let output = Command::new("python3")
        .arg("gen_attestation.py")
        .output()?;  // waits for the script to finish

    // Check the exit code
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("gen_attestation.py failed: {}", stderr).into());
    }

    // Parse stdout as UTF-8, trim trailing newline, and return
    let s = String::from_utf8(output.stdout)?;
    Ok(s.trim_end().to_string())
}

/// Run `run_test.sh` script to check whether the given attack violates invariants provided
/// by the bug receiver.
///
/// This function will panic if `run_test.sh` cannot be spawned, or the script exits with code
/// other than 0 or 1.
///
pub fn check_bug_impl(
    contract_addr: &str,
    block_num: u32,
    bug_filepath: &str,
    inv_filepath: &str,
) -> bool {
    let output = Command::new("./src/run_test.sh")
        .arg(contract_addr)
        .arg(block_num.to_string())
        .arg(bug_filepath)
        .arg(inv_filepath)
        .output()
        .expect("failed to spawn run_test.sh");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    match (code, stdout.as_str()) {
        (0, s) if s.eq_ignore_ascii_case("success") => false,
        (1, s) if s.eq_ignore_ascii_case("fail") => {
            // bug violates invariants
            true
        }
        (other, s) => {
            panic!(
                "run_test.sh returned unexpected code {} with stdout={:?} stderr={:?}",
                other, s, stderr
            );
        }
    }
}

fn main() {
    //let bug_file = env::var("BUG_FILE").map_err(|_| "Environment variable BUG_FILE is not set").unwrap();
    //let block_num_file= env::var("BLOCK_NUM_FILE").map_err(|_| "Environment variable BLOCK_NUM_FILE is not set").unwrap();
    //let test_file = env::var("TEST_FILE").map_err(|_| "Environment variable TEST_FILE is not set").unwrap();
    //let contract_addr_file = env::var("CONTRACT_ADDR_FILE").map_err(|_| "Environment variable CONTRACT_ADDR_FILE is not set").unwrap();

    // Get everthing you need for the bug check
    let block_num_file = "data/block.txt";
    let contract_addr_file = "data/addr.txt";
    let bug_file = "data/bug_cond.sol";
    let test_file = "data/bug_report.sol";

    let block_num = read_block_num(&block_num_file).unwrap();
    let contract_addr = read_contract_addr(&contract_addr_file).unwrap();
    // Check the correctness of the bug
    let check = check_bug_impl(&contract_addr, block_num, &bug_file, &test_file);

    assert!(check, "Bug check failed");
}
