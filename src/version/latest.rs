//! Implementations and functionality that are only required for the latest version
//!
//! We import everything from current version - as if it's just part of that file as well.

// Just use everything from the current version:
use super::v0_3::*;

use super::{Keyed, PlaintextContent, PlaintextEntry, PlaintextField};
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
    pub fn from_plaintext(pwd: String, content: PlaintextContent) -> Self {
        let pwd_salt = SaltString::generate(&mut OsRng); // Have to use OsRng here for CSPRNG
        let iv = thread_rng().gen::<[u8; 16]>().to_vec();

        let hashed_key = hash_key(pwd_salt.as_salt(), &pwd);
        let token = encrypt(ENCRYPT_TOKEN, &iv, &hashed_key);

        let inner = content
            .entries
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
            last_update: content.last_update,
            inner,
        })
    }

    /// Produces the `PlaintextContent` corresponding to the data contained here
    ///
    /// This method should only ever be called once a key has been supplied. A return of `Err(())`
    /// indicates that the decryption key was incorrect.
    #[rustfmt::skip]
    pub fn to_plaintext(self) -> Result<PlaintextContent, ()> {
        let key = self.key.as_ref().expect("`to_plaintext` called without supplied key");
        let iv = self.content.iv.as_ref();

        let entries = self.content.inner
            .into_iter()
            .map(|e| {
                let fields = e.fields
                    .into_iter()
                    .map(|f| {
                        let (value, protected) = match f.value {
                            Value::Basic(s) => {
                                (s, false)
                            }
                            Value::Protected(bs) => {
                                let decrypted_bytes = decrypt(bs.as_ref(), iv, key)
                                    .ok_or(())?;
                                let decrypted_string = String::from_utf8(decrypted_bytes)
                                    .map_err(|_| ())?;

                                (decrypted_string, true)
                            }
                        };

                        Ok(PlaintextField {
                            name: f.name,
                            value,
                            protected,
                        })
                    })
                    .collect::<Result<_, _>>()?;

                Ok(PlaintextEntry {
                    name: e.name,
                    tags: e.tags,
                    fields,
                    first_added: e.first_added,
                    last_update: e.last_update,
                })
            })
            .collect::<Result<_, _>>()?;

        Ok(PlaintextContent {
            last_update: self.content.last_update,
            entries,
        })
    }
}
