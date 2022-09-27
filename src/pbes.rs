/*
 * Proecedure. Generate a hash with Argon2 crate of length 32
 * Serialize it and place in a file of some format.
 * Encrypt the content using ChaChaPoly AEAD.
 * Deserialize the Argon2 struct from the file and decrypt content
 * */

use serde::{
    de::{self, Deserialize, Deserializer, Error, MapAccess, Visitor},
    ser::{self, Serialize, SerializeStruct, Serializer},
};
use std::{
    fmt::{self},
    io::{self, Read, Write},
};

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, OsRng, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};
use std::fs::File;

use argon2::{Algorithm, Argon2, Params, Version};
use password_hash::{
    self, PasswordHash, PasswordHashString, PasswordHasher, PasswordVerifier, SaltString,
};

pub struct EncryptionScheme<'a> {
    pub kdf: Argon2<'a>,
    pub salt: SaltString,
    pub nonce: Nonce,
}

impl<'a> EncryptionScheme<'a> {
    pub fn encrypt(
        &self,
        password: impl AsRef<[u8]>,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let password_hash = self
            .kdf
            .hash_password(password.as_ref(), &self.salt)
            .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;

        let hash = password_hash.hash.ok_or("No hash found")?;
        let cipher = ChaCha20Poly1305::new_from_slice(hash.as_bytes())
            .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;

        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let encrypted_content = cipher
            .encrypt(&self.nonce, payload)
            .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;
        return Ok(encrypted_content);
    }

    pub fn decrypt(
        &self,
        password: impl AsRef<[u8]>,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let password_hash = self
            .kdf
            .hash_password(password.as_ref(), &self.salt)
            .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;

        let hash = password_hash.hash.ok_or("No hash found")?;
        let cipher = ChaCha20Poly1305::new_from_slice(hash.as_bytes())
            .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;

        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        let plaintext = cipher
            .decrypt(&self.nonce, payload)
            .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;

        return Ok(plaintext);
    }

    pub fn decrypt_file(
        &self,
        password: &str,
        file: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut encrypted_content: Vec<u8> = Vec::new();
        let mut f = File::open(file)?;
        f.read_to_end(&mut encrypted_content)?;
        let decrypted_content = self.decrypt(password, &encrypted_content, file.as_bytes())?;

        let mut f = File::create(file)?;
        f.write_all(&decrypted_content)?;
        Ok(())
    }
    pub fn encrypt_file(
        &self,
        password: &str,
        file: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ec = EncryptionScheme::default();
        let mut f = File::open(file).expect("FAILED TO OPEN FILE");
        let mut content = Vec::new();
        f.read_to_end(&mut content)?;
        let encrypted_content = self.encrypt(password, &content, file.as_bytes())?;
        drop(f);

        let mut f = File::create(file)?;
        f.write_all(&encrypted_content)?;
        Ok(())
    }
}

impl<'a> Serialize for EncryptionScheme<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EncryptionScheme", 3)?;
        let mut ph = match self.kdf.hash_password(b"", &self.salt) {
            Ok(v) => v,
            Err(e) => {
                return Err(ser::Error::custom(e.to_string()));
            }
        };
        ph.hash = None;
        state.serialize_field("kdf", &ph.to_string())?;
        state.serialize_field("salt", self.salt.as_str())?;
        state.serialize_field("nonce", self.nonce.as_slice())?;
        state.end()
    }
}

impl<'de: 'a, 'a> Deserialize<'de> for EncryptionScheme<'a> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Kdf,
            Salt,
            Nonce,
        }

        struct SchemeVisitor;

        impl<'de> Visitor<'de> for SchemeVisitor {
            type Value = EncryptionScheme<'de>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct EncryptionScheme")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut kdf = None;
                let mut salt = None;
                let mut nonce = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Kdf => {
                            if kdf.is_some() {
                                return Err(de::Error::duplicate_field("kdf"));
                            }
                            let val: &str = map.next_value()?;
                            let ph_string = match PasswordHashString::new(val) {
                                Ok(v) => v,
                                Err(e) => return Err(de::Error::custom("Invalid phc string")),
                            };
                            let ph: PasswordHash = ph_string.password_hash();
                            let params: Params = Params::try_from(&ph).unwrap();
                            let version: Version = ph.version.unwrap().try_into().unwrap();
                            let arg = Argon2::new(
                                Algorithm::new(ph.algorithm.as_str()).unwrap(),
                                version,
                                params,
                            );
                            kdf = Some(arg);
                        }
                        Field::Salt => {
                            if salt.is_some() {
                                return Err(de::Error::duplicate_field("salt"));
                            }
                            let val: &str = map.next_value()?;
                            let salt_string = SaltString::new(val).ok();
                            salt = salt_string;
                        }
                        Field::Nonce => {
                            if nonce.is_some() {
                                return Err(de::Error::duplicate_field("nonce"));
                            }
                            let val: Vec<u8> = map.next_value().expect("FAILED");
                            let arr: [u8; 12] = val.try_into().expect("Wrong nonce length");
                            let val = Nonce::from(arr);
                            nonce = Some(val);
                        }
                    }
                }
                let kdf = kdf.ok_or_else(|| de::Error::missing_field("kdf"))?;
                let salt = salt.ok_or_else(|| de::Error::missing_field("salt"))?;
                let nonce = nonce.ok_or_else(|| de::Error::missing_field("nonce"))?;
                Ok(EncryptionScheme {
                    kdf,
                    salt,
                    nonce: nonce,
                })
            }
        }
        const FIELDS: &'static [&'static str] = &["kdf", "salt", "nonce"];
        deserializer.deserialize_struct("EncryptionScheme", FIELDS, SchemeVisitor)
    }
}

impl<'a> Default for EncryptionScheme<'a> {
    fn default() -> Self {
        Self {
            kdf: Argon2::default(),
            salt: SaltString::generate(&mut OsRng),
            nonce: ChaCha20Poly1305::generate_nonce(&mut OsRng),
        }
    }
}
