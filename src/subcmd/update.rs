//! Tools for updating a storage file

use super::print_err_and_exit;
use crate::version::{self, FileContent};
use clap::ArgMatches;
use std::fs::File;
use std::io::{self, Write};

pub fn run(matches: &ArgMatches) {
    let input_file_name = matches.value_of("INPUT").unwrap();
    let output_file_name = matches.value_of("OUTPUT").unwrap();

    let (content, _warning) = version::parse(input_file_name);

    let pwd = rpassword::read_password_from_tty(Some("Please enter the encryption key: "))
        .unwrap_or_else(print_err_and_exit);
    let output_content = content.to_current(pwd);

    let () = File::create(output_file_name)
        .and_then(|mut f| {
            let s = output_content
                .map_err(|()| io::Error::new(io::ErrorKind::Other, "wrong decryption key"))?
                .write();
            write!(f, "{}", s).and_then(|_| f.flush())
        })
        .unwrap_or_else(print_err_and_exit);
}
