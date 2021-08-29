//! Wrapper module for the interface around creating a new storage file

use crate::version::{CurrentFileContent, FileContent};
use clap::ArgMatches;
use std::fmt::Display;
use std::fs::File;
use std::io::Write;
use std::process;

pub fn run(matches: &ArgMatches) {
    let file_name = matches.value_of("FILE").unwrap();

    let mut file = File::create(file_name).unwrap_or_else(print_err_and_exit);

    let pwd = rpassword::read_password_from_tty(Some("Please enter an encryption key: "))
        .unwrap_or_else(print_err_and_exit);

    let content = CurrentFileContent::make_new(pwd);
    let as_string = content.write();

    file.write_all(as_string.as_ref())
        .and_then(|()| file.flush())
        .unwrap_or_else(print_err_and_exit);

    println!(
        "Generation successful! Wrote {} bytes to '{}'",
        as_string.len(),
        file_name
    );
}

// Ideally this would return !, but that's not stable yet :(
fn print_err_and_exit<T>(err: impl Display) -> T {
    eprintln!("{}", err);
    process::exit(1)
}
