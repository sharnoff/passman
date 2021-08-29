//! Creates a config file from its plaintext version

use super::print_err_and_exit;
use crate::version::{CurrentFileContent, FileContent};
use clap::ArgMatches;
use std::fs;

#[rustfmt::skip]
pub fn run(matches: &ArgMatches) {
    let input_file_name = matches.value_of("INPUT").unwrap();
    let output_file_name = matches.value_of("OUTPUT").unwrap();

    let content_str = fs::read_to_string(input_file_name)
        .unwrap_or_else(print_err_and_exit);

    let plaintext = serde_yaml::from_str(&content_str)
        .unwrap_or_else(print_err_and_exit);

    let pwd = rpassword::read_password_from_tty(Some("Please enter a new encryption key: "))
        .unwrap_or_else(print_err_and_exit);

    let encrypted = CurrentFileContent::from_plaintext(pwd, plaintext);
    let output_str = encrypted.write();

    fs::write(output_file_name, &output_str)
        .unwrap_or_else(print_err_and_exit);

    println!(
        "Successfully wrote new encrypted file ({} bytes) to '{}'",
        output_str.len(),
        output_file_name
    );
}
