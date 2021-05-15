//! Version 0.3 of the file format

use super::{CurrentFileContent, EntryMut, EntryRef, EntryTemplate, Keyed, Warning};
use crate::utils::Base64Vec;
use aes_soft::Aes256;
use argon2::password_hash::{Salt, SaltString};
use argon2::{Argon2, PasswordHasher};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::{thread_rng, Rng};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::process::exit;
use std::time::SystemTime;

pub const WARNING: Option<Warning> = None;

static VERSION_STR: &str = "v0.3";

pub fn parse(file_content: String) -> Keyed<FileContent> {
    match serde_yaml::from_str::<FileContent>(&file_content) {
        Ok(c) => {
            assert!(c.version == VERSION_STR);
            Keyed::new(c)
        }
        Err(e) => {
            eprintln!("failed to parse file: {}", e);
            exit(1);
        }
    }
}

fn hash_key(salt: Salt, key: &str) -> Vec<u8> {
    // Number of passes. 5 passes for now - can be adjusted later
    const T_COST: u32 = 5;
    // Memory cost, in KBytes. ~1GB
    const M_COST: u32 = 1_000_000;
    // Number of parallel lanes to use. This version of the argon2 library (0.2) doesn't actually
    // implement the speed increase from parallel lanes.
    const PARALLEL: u32 = 1;

    let hasher = Argon2::new(None, T_COST, M_COST, PARALLEL, argon2::Version::V0x13).unwrap();

    let hash = hasher
        .hash_password_simple(key.as_bytes(), &salt)
        .unwrap()
        .hash
        .unwrap();

    hash.as_bytes().to_vec()
}

// The bounds on salt length in "protected" fields
//
// We can encode the length of the salt in the first four bits of the contents, by adding 16 to it
// afterwards.
const SALT_MIN_LENGTH: usize = 17;
const SALT_MAX_LENGTH: usize = 32;

static ENCRYPT_TOKEN: &[u8] = "encryption token ☺".as_bytes();

fn encrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    // Use a random length salt before the value. If the value is too short (i.e. < 17 bytes),
    // we'll increase the minimum length of the salt so that we always get outputs ≥ 32 bytes.
    //
    // This is to make it harder for an outside observer to find short passwords.

    let min_salt_len = SALT_MAX_LENGTH
        .saturating_sub(val.len())
        .max(SALT_MIN_LENGTH);

    let mut rng = thread_rng();

    // Easiest to just generate with constants and maybe not use all of it.
    let mut max_len_salt: [u8; SALT_MAX_LENGTH] = rng.gen();

    // `gen_range` takes an exclusive upper bound -- MAX_LENGTH is inclusive, so we add 1
    let salt_len = rng.gen_range(min_salt_len, SALT_MAX_LENGTH + 1);
    let salt = &mut max_len_salt[..salt_len];

    encrypt_with_salt(val, salt, iv, key)
}

fn encrypt_with_salt(val: &[u8], salt: &mut [u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    // Encode the length of the salt into its first bit:
    debug_assert!(SALT_MAX_LENGTH - SALT_MIN_LENGTH == 15);
    assert!(SALT_MIN_LENGTH <= salt.len() && salt.len() <= SALT_MAX_LENGTH);
    let len_byte = (salt.len() - SALT_MIN_LENGTH) as u8;
    salt[0] = salt[0] & 0xF0 | len_byte;

    // Collect the salt + value into the vector to encrypt
    let mut full = Vec::with_capacity(salt.len() + val.len());
    full.extend_from_slice(salt);
    full.extend_from_slice(val);

    let cipher = <Cbc<Aes256, Pkcs7>>::new_var(key, iv).unwrap();
    cipher.encrypt_vec(&full)
}

fn decrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let cipher = <Cbc<Aes256, Pkcs7>>::new_var(key, iv).unwrap();
    let mut decrypted = cipher.decrypt_vec(val).ok()?;

    // Refer to the construction in `encrypt`
    let salt_len = (decrypted[0] & 0x0F) as usize + SALT_MIN_LENGTH;
    assert!(SALT_MIN_LENGTH <= salt_len && salt_len <= SALT_MAX_LENGTH);

    decrypted.drain(..salt_len);
    Some(decrypted)
}

#[derive(Serialize, Deserialize)]
pub struct FileContent {
    version: String, // Should always be v0.3
    token: Base64Vec,
    iv: Base64Vec,
    salt: String, // Salt for the encryption password
    last_update: SystemTime,
    inner: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    name: String,
    tags: Vec<String>,
    fields: Vec<Field>,
    first_added: SystemTime,
    last_update: SystemTime,
}

#[derive(Serialize, Deserialize)]
struct Field {
    name: String,
    value: Value,
}

#[derive(Serialize, Deserialize)]
enum Value {
    Basic(String),
    Protected(Base64Vec),
}

impl Keyed<FileContent> {
    /// Creates a new `FileContent` with the given password
    pub fn make_new(pwd: String) -> Self {
        Self::from_entries(pwd, Vec::new(), SystemTime::now())
    }

    /// Produces a `FileContent` from a set of entries
    pub(super) fn from_entries(
        pwd: String,
        entries: Vec<EntryTemplate>,
        last_update: SystemTime,
    ) -> Self {
        let pwd_salt = SaltString::generate(&mut OsRng); // Have to use OsRng here for CSPRNG
        let iv = thread_rng().gen::<[u8; 16]>().to_vec();

        let hashed_key = hash_key(pwd_salt.as_salt(), &pwd);
        let token = encrypt(ENCRYPT_TOKEN, &iv, &hashed_key);

        let inner = entries
            .into_iter()
            .map(|e| Entry {
                name: e.name,
                tags: e.tags,
                fields: e
                    .fields
                    .into_iter()
                    .map(|f| {
                        let value = match f.protected {
                            false => Value::Basic(f.value),
                            true => {
                                let enc = encrypt(f.value.as_bytes(), &iv, &hashed_key);
                                Value::Protected(Base64Vec(enc))
                            }
                        };

                        Field {
                            name: f.name,
                            value,
                        }
                    })
                    .collect(),
                first_added: e.first_added,
                last_update: e.last_update,
            })
            .collect();

        Keyed::new(FileContent {
            version: VERSION_STR.to_owned(),
            token: Base64Vec(token),
            iv: Base64Vec(iv),
            salt: pwd_salt.as_str().to_owned(),
            last_update,
            inner,
        })
    }
}

impl super::FileContent for Keyed<FileContent> {
    fn to_current(self: Box<Self>, _pwd: String) -> Result<Box<CurrentFileContent>, ()> {
        Ok(self)
    }

    fn write(&self) -> String {
        serde_yaml::to_string(&self.content)
            .expect("unrecoverable error: failed to serialize the file content")
    }

    fn set_key(&mut self, key: String) -> Result<(), ()> {
        let hashed = hash_key(Salt::new(&self.content.salt).unwrap(), &key);

        let decrypted_token = decrypt(
            self.content.token.as_ref(),
            self.content.iv.as_ref(),
            &hashed,
        );
        match decrypted_token {
            Some(bs) if bs.as_slice() == ENCRYPT_TOKEN => {
                self.key = Some(hashed.into());
                Ok(())
            }
            _ => Err(()),
        }
    }

    fn unsaved(&self) -> bool {
        self.unsaved
    }

    fn mark_saved(&mut self) {
        self.unsaved = false;
    }

    fn decrypted(&self) -> bool {
        self.key.is_some()
    }

    fn num_entries(&self) -> usize {
        self.content.inner.len()
    }

    fn entry(&self, idx: usize) -> Box<dyn EntryRef + '_> {
        Box::new(Ref {
            entry: &self.content.inner[idx],
            iv: self.content.iv.as_ref(),
            key: self.key.as_ref().map(|vec| vec.as_slice()),
        })
    }

    fn entry_mut(&mut self, idx: usize) -> Box<dyn EntryMut + '_> {
        Box::new(Mut {
            entry: &mut self.content.inner[idx],
            iv: self.content.iv.as_ref(),
            key: self.key.as_ref().map(|vec| vec.as_slice()),
            unsaved: &mut self.unsaved,
            global_update: &mut self.content.last_update,
        })
    }

    fn add_empty_entry(&mut self, name: String) -> usize {
        let idx = self.num_entries();
        let now = SystemTime::now();
        self.content.inner.push(Entry {
            name,
            tags: Vec::new(),
            fields: Vec::new(),
            first_added: now,
            last_update: now,
        });

        self.content.last_update = now;
        self.unsaved = true;
        idx
    }

    fn remove_entry(&mut self, idx: usize) {
        self.content.inner.remove(idx);
        self.content.last_update = SystemTime::now();
        self.unsaved = true;
    }
}

struct Ref<'a> {
    entry: &'a Entry,
    iv: &'a [u8],
    key: Option<&'a [u8]>,
}

struct Mut<'a> {
    entry: &'a mut Entry,
    iv: &'a [u8],
    key: Option<&'a [u8]>,
    unsaved: &'a mut bool,
    global_update: &'a mut SystemTime,
}

macro_rules! impl_entry_ref {
    ($ty:ident) => {
        impl<'a> EntryRef for $ty<'a> {
            fn name(&self) -> &str {
                &self.entry.name
            }

            fn tags(&self) -> Vec<&str> {
                self.entry.tags.iter().map(|s| s.as_str()).collect()
            }

            fn first_added(&self) -> SystemTime {
                self.entry.first_added
            }

            fn last_update(&self) -> SystemTime {
                self.entry.last_update
            }

            fn field_protected(&self, idx: usize) -> bool {
                match &self.entry.fields[idx].value {
                    Value::Basic(_) => false,
                    Value::Protected(_) => true,
                }
            }

            fn field_name(&self, idx: usize) -> &str {
                &self.entry.fields[idx].name
            }

            fn field_value(&self, idx: usize) -> Result<String, ()> {
                let value = &self.entry.fields[idx].value;
                match (value, self.key) {
                    (Value::Basic(s), _) => Ok(s.clone()),
                    (Value::Protected(_), None) => Err(()),
                    (Value::Protected(bs), Some(k)) => {
                        let bytes = decrypt(bs.as_ref(), self.iv, k).ok_or(())?;
                        String::from_utf8(bytes).map_err(|_| ())
                    }
                }
            }

            fn num_fields(&self) -> usize {
                self.entry.fields.len()
            }
        }
    };
}

impl_entry_ref!(Ref);
impl_entry_ref!(Mut);

impl<'a> Mut<'a> {
    /// Internal method to mark the entry as updated
    fn updated(&mut self) {
        let now = SystemTime::now();
        self.entry.last_update = now;
        *self.global_update = now;
        *self.unsaved = true;
    }
}

impl<'a> EntryMut for Mut<'a> {
    fn set_name(&mut self, name: String) {
        self.entry.name = name;
        self.updated();
    }

    fn set_tags(&mut self, tags: Vec<String>) {
        self.entry.tags = tags;
        self.updated();
    }

    fn set_field(&mut self, idx: usize, name: String, val: String) {
        let value = match (self.field_protected(idx), self.key) {
            (false, _) | (true, None) => Value::Basic(val),
            (true, Some(k)) => {
                let encrypted = encrypt(val.as_bytes(), self.iv, k);
                Value::Protected(Base64Vec(encrypted))
            }
        };

        self.entry.fields[idx] = Field { name, value };
        self.updated();
    }

    fn swap_encryption(&mut self, idx: usize) -> Result<(), ()> {
        let key = self.key.ok_or(())?;

        let value = &mut self.entry.fields[idx].value;

        let new_val = match &*value {
            Value::Basic(s) => {
                let bs = encrypt(s.as_bytes(), self.iv, key);
                Value::Protected(Base64Vec(bs))
            }
            Value::Protected(bs) => {
                let s = String::from_utf8(decrypt(bs.as_ref(), self.iv, key).ok_or(())?)
                    .map_err(|_| ())?;
                Value::Basic(s)
            }
        };

        *value = new_val;
        self.updated();
        Ok(())
    }

    fn push_field(&mut self, name: String, value: String) {
        self.entry.fields.push(Field {
            name,
            value: Value::Basic(value),
        });
        self.updated();
    }

    fn remove_field(&mut self, idx: usize) {
        self.entry.fields.remove(idx);
        self.updated();
    }
}

// Small collection of tests for encrypting and decrypting
#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Display;

    fn check_single(val: &[u8], salt: &mut [u8], iv: &[u8], key: &[u8], ctx: impl Display) {
        let encrypted = encrypt_with_salt(val, salt, iv, key);
        let decrypted = decrypt(&encrypted, iv, key).unwrap();
        assert_eq!(val, decrypted, "{}", ctx);
    }

    #[test]
    fn run_all() {
        let cases = &[
            // Longest salt
            ("", 32),
            // Shortest salt
            ("longer password so that we have minimum length", 17),
            // Other, random combinations
            ("foobarbaz", 24),
            ("foobarbaz", 25),
            ("foobarbaz", 26),
            ("foobarbaz", 27),
            ("foobarbaz", 28),
            ("foobarbaz", 29),
            ("foobarbaz", 30),
            ("foobarbaz", 31),
            ("foobarbaz", 32),
        ];

        // 32 totally random bytes.
        let base_salt = b"\x6e\x6f\x20\x73\x65\x72\x69\x6f\x75\x73\x6c\x79\x20\x69\x74\x27\x73\x20\x6a\x75\x73\x74\x20\x72\x61\x6e\x64\x6f\x6d\x20\x3a\x50";
        assert!(base_salt.len() == 32);

        let key_salt = Salt::new("randomsaltstring").unwrap();

        let key = "a temporary key for testing";
        let hashed_key = hash_key(key_salt, key);

        // 16 totally random bytes.
        let iv = b"\x74\x68\x69\x73\x20\x69\x73\x20\x74\x68\x65\x20\x69\x76\x21\x21";
        assert!(iv.len() == 16);

        for (val, salt_len) in cases.iter().cloned() {
            assert!(val.len() + salt_len >= SALT_MAX_LENGTH);

            let mut salt = base_salt[..salt_len].to_vec();
            let ctx = format!("val: {}, salt_len: {}", val, salt_len);
            check_single(val.as_bytes(), &mut salt, iv, &hashed_key, ctx);
        }
    }
}
