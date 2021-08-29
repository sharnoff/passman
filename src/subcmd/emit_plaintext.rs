//! Emits the plaintext version of a file

use super::print_err_and_exit;
use crate::version;
use clap::ArgMatches;
use std::fs;

pub fn run(matches: &ArgMatches) {
    let input_file_name = matches.value_of("INPUT").unwrap();
    let output_file_name = matches.value_of("OUTPUT").unwrap();

    let (content, _warning) = version::parse(input_file_name);

    let pwd = rpassword::read_password_from_tty(Some("Please enter the current encryption key: "))
        .unwrap_or_else(print_err_and_exit);

    let output = content
        .to_current(pwd)
        .and_then(|c| c.to_plaintext())
        .map_err(|()| "error: wrong decryption key")
        .unwrap_or_else(print_err_and_exit);

    let s = serde_yaml::to_string(&output)
        .expect("unrecoverable error: failed to serialize the plaintext content");

    fs::write(output_file_name, s).unwrap_or_else(print_err_and_exit);
}
