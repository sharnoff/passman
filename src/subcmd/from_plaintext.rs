//! Creates a config file from its plaintext version

use super::print_err_and_exit;
use crate::version::{CurrentFileContent, FileContent};
use std::fs;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    /// Sets the input file to read from
    #[clap(short, long, name = "INPUT")]
    input: PathBuf,

    /// Sets the output file to write to
    #[clap(short, long, name = "OUTPUT")]
    output: PathBuf,
}

#[rustfmt::skip]
pub fn run(args: Args) {
    let content_str = fs::read_to_string(args.input)
        .unwrap_or_else(print_err_and_exit);

    let plaintext = serde_yaml::from_str(&content_str)
        .unwrap_or_else(print_err_and_exit);

    let pwd = rpassword::read_password_from_tty(Some("Please enter a new encryption key: "))
        .unwrap_or_else(print_err_and_exit);

    let encrypted = CurrentFileContent::from_plaintext(pwd, plaintext);
    let output_str = encrypted.write();

    fs::write(&args.output, &output_str)
        .unwrap_or_else(print_err_and_exit);

    println!(
        "Successfully wrote new encrypted file ({} bytes) to '{}'",
        output_str.len(),
        args.output.to_string_lossy()
    );
}
