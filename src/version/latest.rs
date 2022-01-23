//! Implementations and functionality that are only required for the latest version
//!
//! We import everything from current version - as if it's just part of that file as well.

// Just use everything from the current version:
use super::v0_4::*;

use super::errors::DecryptError;
use super::{Keyed, PlaintextContent, PlaintextEntry, PlaintextField, PlaintextValue};
use crate::utils::Base64Vec;
use argon2::password_hash::SaltString;
use rand::{thread_rng, Rng};
use rand_core::OsRng;

impl Keyed<FileContent> {
    /// Creates a new `FileContent` with the given password
    pub fn make_new(pwd: String) -> Self {
        Self::from_plaintext(pwd, PlaintextContent::init())
    }

    /// Produces a `FileContent` from the plaintext content
    #[rustfmt::skip]
    pub fn from_plaintext(pwd: String, content: PlaintextContent) -> Self {
        let pwd_salt = SaltString::generate(&mut OsRng); // Have to use OsRng here for CSPRNG
        let iv = thread_rng().gen::<[u8; 16]>();

        let hashed_key = hash_key(pwd_salt.as_salt(), &pwd);
        let token = encrypt(ENCRYPT_TOKEN, &iv, &hashed_key);

        Keyed::new(FileContent {
            version: VERSION_STR.to_owned(),
            token: Base64Vec(token),
            iv: Base64Vec(iv.to_vec()),
            salt: pwd_salt.as_str().to_owned(),
            last_update: content.last_update,
            inner: content.entries.into_iter().map(|e| Entry {
                name: e.name,
                tags: e.tags,
                first_added: e.first_added,
                last_update: e.last_update,
                fields: e.fields.into_iter().map(|f| Field {
                    name: f.name,
                    value: match f.value {
                        PlaintextValue::Manual { value, protected: false } => Value::Basic(value),
                        PlaintextValue::Manual { value, protected: true } => {
                            Value::Protected(
                                Base64Vec(encrypt(value.as_bytes(), &iv, &hashed_key))
                            )
                        },
                        PlaintextValue::Totp { issuer, secret } => {
                            let secret = Base64Vec(encrypt(secret.as_bytes(), &iv, &hashed_key));
                            Value::Totp { issuer, secret }
                        }
                    },
                }).collect()
            }).collect(),
        })
    }

    /// Produces the `PlaintextContent` corresponding to the data contained here
    ///
    /// This method should only ever be called once a key has been supplied. A return of `Err`
    /// indicates that the decryption key was incorrect.
    #[rustfmt::skip]
    pub fn to_plaintext(self) -> Result<PlaintextContent, DecryptError> {
        let key = self.key.as_ref().expect("`to_plaintext` called without supplied key");
        let iv = self.content.iv.as_ref();

        Ok(PlaintextContent {
            last_update: self.content.last_update,
            entries: self.content.inner.into_iter().map(|e| Ok(PlaintextEntry {
                name: e.name,
                tags: e.tags,
                first_added: e.first_added,
                last_update: e.last_update,
                fields: e.fields.into_iter().map(|f| Ok(PlaintextField {
                    name: f.name,
                    value: match f.value {
                        Value::Basic(s) => {
                            PlaintextValue::Manual { value: s, protected: false }
                        }
                        Value::Protected(bs) => {
                            let value = decrypt_string(bs.as_ref(), iv, key)?;
                            PlaintextValue::Manual { value, protected: true }
                        }
                        Value::Totp { issuer, secret } => {
                            let secret = decrypt_string(secret.as_ref(), iv, key)?;
                            PlaintextValue::Totp { issuer, secret }
                        }
                    }
                })).collect::<Result<_, _>>()?,
            })).collect::<Result<_, _>>()?,
        })
    }
}
