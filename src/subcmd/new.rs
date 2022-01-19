//! Wrapper module for the interface around creating a new storage file

use super::print_err_and_exit;
use crate::version::{CurrentFileContent, FileContent};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    /// Sets the file to write to
    #[clap(name = "FILE")]
    file_name: PathBuf,
}

pub fn run(args: Args) {
    let mut file = File::create(&args.file_name).unwrap_or_else(print_err_and_exit);

    let pwd = rpassword::read_password_from_tty(Some("Please enter an encryption key: "))
        .unwrap_or_else(print_err_and_exit);

    let content = CurrentFileContent::make_new(pwd);
    let as_string = content.write();

    file.write_all(as_string.as_ref())
        .and_then(|()| file.flush())
        .unwrap_or_else(print_err_and_exit);

    println!(
        "Generation successful! Wrote {} bytes to {:?}",
        as_string.len(),
        args.file_name,
    );
}
