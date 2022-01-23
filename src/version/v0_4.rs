//! Version 0.4 of the file format

use super::{
    CurrentFileContent, DecryptError, GetValueError, Keyed, PlaintextValue, SetFieldError,
    SwapEncryptionError, UnsupportedFeature, ValueKind, Warning,
};
use crate::utils::Base64Vec;
use argon2::password_hash::Salt;
use google_authenticator::GA_AUTH;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::mem::take;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};

pub const WARNING: Option<Warning> = None;

pub static VERSION_STR: &str = "v0.4";

// Some pieces of this file format are taken directly from v0.3; we'll import them here:
pub use super::v0_3::{decrypt, decrypt_string, encrypt, hash_key, ENCRYPT_TOKEN};

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

#[derive(Serialize, Deserialize)]
pub struct FileContent {
    pub version: String, // Should always be v0.4
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
    #[serde(rename = "basic")]
    Basic(String),
    #[serde(rename = "protected")]
    Protected(Base64Vec),
    #[serde(rename = "totp")]
    Totp { issuer: String, secret: Base64Vec },
}

impl super::FileContent for Keyed<FileContent> {
    fn to_current(
        mut self: Box<Self>,
        pwd: String,
    ) -> Result<Box<CurrentFileContent>, DecryptError> {
        self.set_key(pwd)?;
        Ok(self)
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
        #[rustfmt::skip]
        let value = match take(&mut b.value).expect("no value set in builder") {
            PlaintextValue::Manual { value, protected: false } => {
                Value::Basic(value.clone())
            },
            PlaintextValue::Manual { value, protected: true } => {
                let k = self.crypt.key
                    .ok_or(SetFieldError::ContentsNotUnlocked(ValueKind::Totp))?;

                Value::Protected(
                    Base64Vec(encrypt(value.as_bytes(), self.crypt.iv, k))
                )
            }
            PlaintextValue::Totp { issuer, secret } => {
                let k = self.crypt.key
                    .ok_or(SetFieldError::ContentsNotUnlocked(ValueKind::Totp))?;

                Value::Totp {
                    issuer: issuer.clone(),
                    secret: Base64Vec(encrypt(secret.as_bytes(), self.crypt.iv, k)),
                }
            }
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

#[rustfmt::skip]
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
                    Value::Totp { .. } => ValueKind::Totp,
                }
            }

            fn value(&self) -> Result<String, GetValueError> {
                match (&self.field.value, self.crypt.key) {
                    (Value::Basic(s), _) => Ok(s.clone()),
                    (Value::Protected(bs), Some(k)) => {
                        Ok(decrypt_string(bs.as_ref(), self.crypt.iv, k)?)
                    }
                    (Value::Totp { secret, .. }, Some(k)) => {
                        let secret_plaintext = decrypt_string(secret.as_ref(), self.crypt.iv, k)?;
                        let unix_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        // TOTP works with 30-second time slices, 
                        let time_slice = unix_time / 30;
                        let code = GA_AUTH.get_code(&secret_plaintext, time_slice)
                            .map_err(|_| GetValueError::BadTotpSecret)?;
                        let secs_remaining = 30 - unix_time % 30;
                        crate::utils::send_refresh_tick_after_1_second();
                        Ok(format!("{code}  (00:{secs_remaining:02} remaining)"))
                    }
                    (_, None) => Err(GetValueError::ContentsNotUnlocked),
                }
            }

            fn plaintext_value(&self) -> Result<PlaintextValue, GetValueError> {
                match (&self.field.value, self.crypt.key) {
                    (Value::Basic(s), _) => {
                        Ok(PlaintextValue::Manual { value: s.clone(), protected: false })
                    }
                    (Value::Protected(bs), Some(k)) => {
                        let value = decrypt_string(bs.as_ref(), self.crypt.iv, k)?;
                        Ok(PlaintextValue::Manual { value, protected: true })
                    }
                    (Value::Totp { secret, issuer }, Some(k)) => {
                        let secret = decrypt_string(secret.as_ref(), self.crypt.iv, k)?;
                        Ok(PlaintextValue::Totp { secret, issuer: issuer.clone() })
                    }
                    (_, None) => Err(GetValueError::ContentsNotUnlocked),
                }
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
            Value::Totp { .. } => return Err(SwapEncryptionError::IsTotp),
        };

        self.field.value = new_val;
        self.updated();
        Ok(())
    }
}

struct FieldBuilder {
    name: Option<String>,
    value: Option<PlaintextValue>,
}

impl super::FieldBuilder for FieldBuilder {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn make_manual(&mut self) {}

    fn make_totp(&mut self) -> Result<(), UnsupportedFeature> {
        Ok(())
    }

    fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    fn set_value(&mut self, value: PlaintextValue) {
        self.value = Some(value);
    }
}
