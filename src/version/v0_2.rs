//! Version 0.2 of the file format

use super::{
    CurrentFileContent, DecryptError, GetValueError, Keyed, PlaintextContent, PlaintextEntry,
    PlaintextField, PlaintextValue, SetFieldError, SwapEncryptionError, UnsupportedFeature,
    ValueKind, Warning,
};
use crate::utils::Base64Vec;
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::any::Any;
use std::mem::take;
use std::process::exit;
use std::time::SystemTime;

pub const WARNING: Option<Warning> = Some(Warning {
    // There's actually multiple reasons -- primarily that individually-encrypted entries aren't
    // salted, but also that the master key isn't extended in any way beyond a simple hash.
    reason: "v0.2 is deprecated for security reasons",
});

static VERSION_STR: &str = "v0.2";

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

fn hash_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.finalize().into()
}

fn encrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = <Cbc<Aes256, Pkcs7>>::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(val)
}

fn decrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let cipher = <Cbc<Aes256, Pkcs7>>::new_from_slices(&key, iv).unwrap();
    cipher.decrypt_vec(val).ok()
}

fn decrypt_string(val: &[u8], iv: &[u8], key: &[u8]) -> Result<String, DecryptError> {
    let bytes = decrypt(val, iv, key).ok_or(DecryptError::BadCrypt)?;
    String::from_utf8(bytes).map_err(|_| DecryptError::BadUtf8)
}

static ENCRYPT_TOKEN: &[u8] = "encryption token ☺".as_bytes();

#[derive(Serialize, Deserialize)]
pub struct FileContent {
    version: String, // Should always be v0.2
    token: Base64Vec,
    iv: Base64Vec,
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

impl super::FileContent for Keyed<FileContent> {
    fn to_current(
        mut self: Box<Self>,
        pwd: String,
    ) -> Result<Box<CurrentFileContent>, DecryptError> {
        if !self.decrypted() {
            self.set_key(pwd.clone())?;
        }

        let key = self.key.as_ref().unwrap();
        let iv = self.content.iv.as_ref();

        let entries = self
            .content
            .inner
            .into_iter()
            .map(|e| {
                Ok(PlaintextEntry {
                    name: e.name,
                    tags: e.tags,
                    fields: e
                        .fields
                        .into_iter()
                        .map(|f| {
                            let (value, protected) = match f.value {
                                Value::Basic(s) => (s, false),
                                Value::Protected(bs) => {
                                    let decrypted = decrypt_string(bs.as_ref(), iv, key)?;
                                    (decrypted, true)
                                }
                            };

                            Ok(PlaintextField {
                                name: f.name,
                                value: PlaintextValue::Manual { value, protected },
                            })
                        })
                        .collect::<Result<_, _>>()?,
                    first_added: e.first_added,
                    last_update: e.last_update,
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(Box::new(CurrentFileContent::from_plaintext(
            pwd,
            PlaintextContent {
                last_update: self.content.last_update,
                entries,
            },
        )))
    }

    fn write(&self) -> String {
        serde_yaml::to_string(&self.content)
            .expect("unrecoverable error: failed to serialize the file content")
    }

    fn set_key(&mut self, key: String) -> Result<(), DecryptError> {
        let hashed = hash_key(&key);

        // Check that decrypting the token produces the correct value
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
