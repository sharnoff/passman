//! Implementations of miscelaneous other subcommands provided

use std::fmt::Display;
use std::process;

pub mod emit_plaintext;
pub mod from_plaintext;
pub mod new;
pub mod update;

/// Helper function used by subcommands
///
/// Ideally, this would return `!`, but that's not stable yet :(
fn print_err_and_exit<T>(err: impl Display) -> T {
    eprintln!("{}", err);
    process::exit(1)
}
