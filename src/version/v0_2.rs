//! Version 0.2 of the file format

use super::{
    CurrentFileContent, EntryMut, EntryRef, Keyed, PlaintextContent, PlaintextEntry,
    PlaintextField, Warning,
};
use crate::utils::Base64Vec;
use aes_soft::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    hasher.input(key.as_bytes());
    hasher.result().into()
}

fn encrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = <Cbc<Aes256, Pkcs7>>::new_var(key, iv).unwrap();
    cipher.encrypt_vec(val)
}

fn decrypt(val: &[u8], iv: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let cipher = <Cbc<Aes256, Pkcs7>>::new_var(&key, iv).unwrap();
    cipher.decrypt_vec(val).ok()
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
    fn to_current(mut self: Box<Self>, pwd: String) -> Result<Box<CurrentFileContent>, ()> {
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
                                    let decrypted = decrypt(bs.as_ref(), iv, key)
                                        .ok_or(())
                                        .and_then(|bs| String::from_utf8(bs).map_err(|_| ()))?;
                                    (decrypted, true)
                                }
                            };

                            Ok(PlaintextField {
                                name: f.name,
                                value,
                                protected,
                            })
                        })
                        .collect::<Result<_, ()>>()?,
                    first_added: e.first_added,
                    last_update: e.last_update,
                })
            })
            .collect::<Result<_, ()>>()?;

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

    fn set_key(&mut self, key: String) -> Result<(), ()> {
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
