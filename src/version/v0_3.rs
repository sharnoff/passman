//! Version 0.3 of the file format

use super::{
    CurrentFileContent, DecryptError, GetValueError, Keyed, PlaintextValue, SetFieldError,
    SwapEncryptionError, UnsupportedFeature, ValueKind, Warning,
};
use crate::utils::Base64Vec;
use aes::Aes256;
use argon2::password_hash::Salt;
use argon2::{Argon2, PasswordHasher};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::mem::take;
use std::process::exit;
use std::time::SystemTime;

pub const WARNING: Option<Warning> = None;

pub static VERSION_STR: &str = "v0.3";

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

// Returns the parameters we use for the hasher
fn argon_params() -> argon2::Params {
    // Number of passes. 5 passes for now - can be adjusted later
    const T_COST: u32 = 5;
    // Memory cost, in KBytes. ~1GB
    const M_COST: u32 = 1_000_000;
    // Number of parallel lanes to use. This version of the argon2 library (0.2) doesn't actually
    // implement the speed increase from parallel lanes.
    const PARALLEL: u32 = 1;

    let mut builder = argon2::ParamsBuilder::new();
    builder.t_cost(T_COST).unwrap();
    builder.m_cost(M_COST).unwrap();
    builder.p_cost(PARALLEL).unwrap();
    builder.params().unwrap()
}

pub fn hash_key(salt: Salt, key: &str) -> Vec<u8> {
    let hasher = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params(),
    );

    let hash = hasher
        .hash_password(key.as_bytes(), &salt)
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

pub static ENCRYPT_TOKEN: &[u8] = "encryption token ☺".as_bytes();

pub fn encrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
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

    let salt_len = rng.gen_range(min_salt_len..=SALT_MAX_LENGTH);
    let salt = &mut max_len_salt[..salt_len];

    encrypt_with_salt(val, salt, iv, key)
}

pub fn encrypt_with_salt(val: &[u8], salt: &mut [u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    // Encode the length of the salt into its first bit:
    debug_assert!(SALT_MAX_LENGTH - SALT_MIN_LENGTH == 15);
    assert!(SALT_MIN_LENGTH <= salt.len() && salt.len() <= SALT_MAX_LENGTH);
    let len_byte = (salt.len() - SALT_MIN_LENGTH) as u8;
    salt[0] = salt[0] & 0xF0 | len_byte;

    // Collect the salt + value into the vector to encrypt
    let mut full = Vec::with_capacity(salt.len() + val.len());
    full.extend_from_slice(salt);
    full.extend_from_slice(val);

    let cipher = <Cbc<Aes256, Pkcs7>>::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(&full)
}

pub fn decrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let cipher = <Cbc<Aes256, Pkcs7>>::new_from_slices(key, iv).unwrap();
    let mut decrypted = cipher.decrypt_vec(val).ok()?;

    // Refer to the construction in `encrypt`
    let salt_len = (decrypted[0] & 0x0F) as usize + SALT_MIN_LENGTH;
    assert!(SALT_MIN_LENGTH <= salt_len && salt_len <= SALT_MAX_LENGTH);

    decrypted.drain(..salt_len);
    Some(decrypted)
}

pub fn decrypt_string(val: &[u8], iv: &[u8], key: &[u8]) -> Result<String, DecryptError> {
    let bytes = decrypt(val, iv, key).ok_or(DecryptError::BadCrypt)?;
    String::from_utf8(bytes).map_err(|_| DecryptError::BadUtf8)
}

#[derive(Serialize, Deserialize)]
pub struct FileContent {
    pub version: String, // Should always be v0.3
    pub token: Base64Vec,
    pub iv: Base64Vec,
    pub salt: String, // Salt for the encryption password
    pub last_update: SystemTime,
    pub inner: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub tags: Vec<String>,
    pub fields: Vec<Field>,
    pub first_added: SystemTime,
    pub last_update: SystemTime,
}

#[derive(Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: Value,
}

#[derive(Serialize, Deserialize)]
pub enum Value {
    Basic(String),
    Protected(Base64Vec),
}

impl super::FileContent for Keyed<FileContent> {
    fn to_current(self: Box<Self>, pwd: String) -> Result<Box<CurrentFileContent>, DecryptError> {
        // Because v0.3 uses the same password hash & encryption as v0.4, we can go directly
        // instead of passing through plaintext first:
        use super::v0_4;

        let this = self.content;

        #[rustfmt::skip]
        let content_v0_4 = v0_4::FileContent {
            version: v0_4::VERSION_STR.to_owned(),
            token: this.token,
            iv: this.iv,
            salt: this.salt,
            last_update: this.last_update,
            inner: this.inner.into_iter().map(|e| v0_4::Entry {
                name: e.name,
                tags: e.tags,
                first_added: e.first_added,
                last_update: e.last_update,
                fields: e.fields.into_iter().map(|f| v0_4::Field {
                    name: f.name,
                    value: match f.value {
                        Value::Basic(s) => v0_4::Value::Basic(s),
                        Value::Protected(bs) => v0_4::Value::Protected(bs),
                    },
                })
                .collect(),
            }).collect(),
        };

        Box::new(Keyed::new(content_v0_4)).to_current(pwd)
    }

    fn write(&self) -> String {
        serde_yaml::to_string(&self.content)
            .expect("unrecoverable error: failed to serialize the file content")
    }

    fn set_key(&mut self, key: String) -> Result<(), DecryptError> {
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
            _ => Err(DecryptError::BadCrypt),
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

    fn entry(&self, idx: usize) -> Box<dyn super::EntryRef + '_> {
        Box::new(EntryRef {
            entry: &self.content.inner[idx],
            crypt: CryptStateRef {
                iv: self.content.iv.as_ref(),
                key: self.key.as_ref().map(|vec| vec.as_slice()),
            },
        })
    }

    fn entry_mut(&mut self, idx: usize) -> Box<dyn super::EntryMut + '_> {
        Box::new(EntryMut {
            entry: &mut self.content.inner[idx],
            crypt: CryptStateRef {
                iv: self.content.iv.as_ref(),
                key: self.key.as_ref().map(|vec| vec.as_slice()),
            },
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

#[derive(Copy, Clone)]
struct CryptStateRef<'a> {
    iv: &'a [u8],
    key: Option<&'a [u8]>,
}

struct EntryRef<'a> {
    entry: &'a Entry,
    crypt: CryptStateRef<'a>,
}

struct EntryMut<'a> {
    entry: &'a mut Entry,
    crypt: CryptStateRef<'a>,
    unsaved: &'a mut bool,
    global_update: &'a mut SystemTime,
}

macro_rules! impl_entry_ref {
    ($ty:ident) => {
        impl<'a> super::EntryRef for $ty<'a> {
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

            fn field(&self, idx: usize) -> Box<dyn super::FieldRef + '_> {
                Box::new(FieldRef {
                    field: &self.entry.fields[idx],
                    crypt: self.crypt,
                })
            }

            fn num_fields(&self) -> usize {
                self.entry.fields.len()
            }
        }
    };
}

impl_entry_ref!(EntryRef);
impl_entry_ref!(EntryMut);

impl<'a> EntryMut<'a> {
    /// Internal method to mark the entry as updated
    fn updated(&mut self) {
        let now = SystemTime::now();
        self.entry.last_update = now;
        *self.global_update = now;
        *self.unsaved = true;
    }
}

impl<'a> super::EntryMut for EntryMut<'a> {
    fn set_name(&mut self, name: String) {
        self.entry.name = name;
        self.updated();
    }

    fn set_tags(&mut self, tags: Vec<String>) {
        self.entry.tags = tags;
        self.updated();
    }

    fn field_mut(&mut self, idx: usize) -> Box<dyn super::FieldMut + '_> {
        Box::new(FieldMut {
            field: &mut self.entry.fields[idx],
            crypt: self.crypt,
            unsaved: self.unsaved,
            entry_update: &mut self.entry.last_update,
            global_update: self.global_update,
        })
    }

    fn field_builder(&self) -> Box<dyn super::FieldBuilder> {
        Box::new(FieldBuilder {
            name: None,
            value: None,
            is_protected: None,
        })
    }

    fn set_field(
        &mut self,
        idx: usize,
        mut builder: Box<dyn super::FieldBuilder>,
    ) -> Result<(), SetFieldError> {
        let b = builder
            .as_any_mut()
            .downcast_mut::<FieldBuilder>()
            .expect("wrong type given back to `set_field`");

        let name = take(&mut b.name).expect("no name set in builder");
        let value = take(&mut b.value).expect("no value set in builder");
        let is_protected = b.is_protected.expect("no is_protected set in builder");

        let value = match (is_protected, self.crypt.key) {
            (true, _) => Value::Basic(value),
            (false, Some(k)) => {
                let encrypted = encrypt(value.as_bytes(), self.crypt.iv, k);
                Value::Protected(Base64Vec(encrypted))
            }
            (false, None) => return Err(SetFieldError::ContentsNotUnlocked(ValueKind::Protected)),
        };

        let field = Field { name, value };
        if idx == self.entry.fields.len() {
            self.entry.fields.push(field);
        } else {
            self.entry.fields[idx] = field;
        }

        self.updated();
        Ok(())
    }

    fn remove_field(&mut self, idx: usize) {
        self.entry.fields.remove(idx);
        self.updated();
    }
}

struct FieldRef<'a> {
    field: &'a Field,
    crypt: CryptStateRef<'a>,
}

struct FieldMut<'a> {
    field: &'a mut Field,
    crypt: CryptStateRef<'a>,
    unsaved: &'a mut bool,
    entry_update: &'a mut SystemTime,
    global_update: &'a mut SystemTime,
}

macro_rules! impl_field_ref {
    ($ty:ident) => {
        impl<'a> super::FieldRef for $ty<'a> {
            fn name(&self) -> &str {
                &self.field.name
            }

            fn value_kind(&self) -> ValueKind {
                match &self.field.value {
                    Value::Basic(_) => ValueKind::Basic,
                    Value::Protected(_) => ValueKind::Protected,
                }
            }

            fn value(&self) -> Result<String, GetValueError> {
                match (&self.field.value, self.crypt.key) {
                    (Value::Basic(s), _) => Ok(s.clone()),
                    (Value::Protected(_), None) => Err(GetValueError::ContentsNotUnlocked),
                    (Value::Protected(bs), Some(k)) => {
                        Ok(decrypt_string(bs.as_ref(), self.crypt.iv, k)?)
                    }
                }
            }

            fn plaintext_value(&self) -> Result<PlaintextValue, GetValueError> {
                let value = self.value()?;
                let protected = match &self.field.value {
                    Value::Basic(_) => false,
                    Value::Protected(_) => true,
                };

                Ok(PlaintextValue::Manual { value, protected })
            }
        }
    };
}

impl_field_ref!(FieldRef);
impl_field_ref!(FieldMut);

impl<'a> FieldMut<'a> {
    /// Internal method to mark the entry as updated
    fn updated(&mut self) {
        let now = SystemTime::now();
        *self.entry_update = now;
        *self.global_update = now;
        *self.unsaved = true;
    }
}

impl<'a> super::FieldMut for FieldMut<'a> {
    fn swap_encryption(&mut self) -> Result<(), SwapEncryptionError> {
        let key = self
            .crypt
            .key
            .ok_or(SwapEncryptionError::ContentsNotUnlocked)?;

        let new_val = match &self.field.value {
            Value::Basic(s) => {
                let bs = encrypt(s.as_bytes(), self.crypt.iv, key);
                Value::Protected(Base64Vec(bs))
            }
            Value::Protected(bs) => Value::Basic(decrypt_string(bs.as_ref(), self.crypt.iv, key)?),
        };

        self.field.value = new_val;
        self.updated();
        Ok(())
    }
}

struct FieldBuilder {
    name: Option<String>,
    value: Option<String>,
    is_protected: Option<bool>,
}

impl super::FieldBuilder for FieldBuilder {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn make_manual(&mut self) {}

    fn make_totp(&mut self) -> Result<(), UnsupportedFeature> {
        Err(UnsupportedFeature::Totp)
    }

    fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    fn set_value(&mut self, value: PlaintextValue) {
        match value {
            PlaintextValue::Manual { value, protected } => {
                self.value = Some(value);
                self.is_protected = Some(protected);
            }
            PlaintextValue::Totp { .. } => panic!("unexpected unsupported TOTP value"),
        }
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
