//! Various utility functions that aren't directly tied to the primary function of the program

use std::io::{stdin, stdout, Write};

use crossterm::cursor::MoveToColumn;
use crossterm::event::{self, Event, KeyCode};
use crossterm::style::Print;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use crossterm::QueueableCommand;

use chrono::{DateTime, Local};
use std::time::SystemTime;

use aes_soft::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::{thread_rng, Rng};
use sha2::digest::Digest;
use sha2::Sha256;

pub fn format_time(time: SystemTime) -> String {
    let time: DateTime<Local> = time.into();
    time.to_rfc2822()
}

pub fn comma_strings<S: AsRef<str>>(strs: &[S]) -> String {
    if strs.is_empty() {
        return "<None>".into();
    }

    let mut result: String = strs[0].as_ref().into();
    for s in strs[1..].iter() {
        result.push(',');
        result.push_str(s.as_ref());
    }
    result
}

/// Reads a password from the terminal
///
/// This function puts the terminal into raw mode and displays asterisks in place of actual
/// characters. Deletion with backspace is supported.
///
/// This function also expects a blank newline to do all input handling
pub fn read_password() -> String {
    enable_raw_mode().unwrap();

    let mut pwd = String::new();
    let mut len = 0_usize;
    loop {
        let mut line: String = ">> ".into();
        line.push_str("*".repeat(len).as_ref());

        // Redraw on every input (even invalid ones, because it's simpler that way)
        stdout()
            .queue(Clear(ClearType::CurrentLine))
            .unwrap()
            .queue(MoveToColumn(0))
            .unwrap()
            .queue(Print(line))
            .unwrap()
            .flush()
            .unwrap();

        let key = match event::read().unwrap() {
            Event::Key(k) => k,
            _ => continue,
        };

        match key.code {
            KeyCode::Char(c) => {
                pwd.push(c);
                len += 1;
            }
            KeyCode::Backspace if len != 0 => {
                pwd.pop();
                len -= 1;
            }
            KeyCode::Enter => break,
            _ => (),
        }
    }

    disable_raw_mode().unwrap();
    println!("");
    pwd
}

pub fn read_valid<'a, F, R>(mut valid: F) -> R
where
    F: 'a + FnMut(&str) -> Result<R, &str>,
    R: 'a,
{
    loop {
        let mut input = String::new();
        stdin().read_line(&mut input).unwrap();
        match valid(input.trim()) {
            Ok(r) => return r,
            Err(e) => {
                print!("{}", e);
                stdout().flush().unwrap();
            }
        }
    }
}

pub fn read_nonempty_string(err_msg: &str) -> String {
    loop {
        let mut input = String::new();
        stdin().read_line(&mut input).unwrap();
        let t = input.trim();
        match t {
            "" => {
                print!("{}", err_msg);
                stdout().flush().unwrap();
                continue;
            }
            _ => return t.into(),
        }
    }
}

/// Returns true if yes, false if no
pub fn query_yes_no() -> bool {
    read_valid(|s| match s.to_lowercase().as_ref() {
        "y" | "yes" => Ok(true),
        "n" | "no" => Ok(false),
        _ => Err("Please enter '(Y)es' or '(N)o': "),
    })
}

// Encryption stuff

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn hash(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.input(key.as_bytes());
    hasher.result().into()
}

pub fn gen_iv() -> [u8; 16] {
    thread_rng().gen()
}

pub fn encrypt_with(key: &str, value: &[u8], iv: &[u8]) -> Vec<u8> {
    let key = hash(key);
    let cipher = Aes256Cbc::new_var(&key, iv).unwrap();

    cipher.encrypt_vec(value)
}

pub fn decrypt_with(key: &str, value: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    let key = hash(key);
    let cipher = Aes256Cbc::new_var(&key, iv).unwrap();

    match cipher.decrypt_vec(value) {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}
