//! Tools for updating a storage file

use super::print_err_and_exit;
use crate::version::{self, FileContent};
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct Args {
    /// Sets the input file to read from
    #[clap(short, long)]
    input: PathBuf,

    /// Sets the output file to write to
    #[clap(short, long)]
    output: PathBuf,
}

pub fn run(args: Args) {
    let (content, _warning) = version::parse(&args.input);

    let pwd = rpassword::read_password_from_tty(Some("Please enter the encryption key: "))
        .unwrap_or_else(print_err_and_exit);
    let output_content = content.to_current(pwd);

    let () = File::create(args.output)
        .and_then(|mut f| {
            let s = output_content
                .map_err(|()| io::Error::new(io::ErrorKind::Other, "wrong decryption key"))?
                .write();
            write!(f, "{}", s).and_then(|_| f.flush())
        })
        .unwrap_or_else(print_err_and_exit);
}
