//! Emits the plaintext version of a file

use super::print_err_and_exit;
use crate::version;
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

pub fn run(args: Args) {
    let (content, _warning) = version::parse(&args.input);

    let pwd = rpassword::read_password_from_tty(Some("Please enter the current encryption key: "))
        .unwrap_or_else(print_err_and_exit);

    let output = content
        .to_current(pwd)
        .and_then(|c| c.to_plaintext())
        .map_err(|_| "error: decryption failed")
        .unwrap_or_else(print_err_and_exit);

    let s = serde_yaml::to_string(&output)
        .expect("unrecoverable error: failed to serialize the plaintext content");

    fs::write(args.output, s).unwrap_or_else(print_err_and_exit);
}
