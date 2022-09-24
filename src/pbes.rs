/*
 * Proecedure. Generate a hash with Argon2 crate of length 32
 * Serialize it and place in a file of some format.
 * Encrypt the content using ChaChaPoly AEAD.
 * Deserialize the Argon2 struct from the file and decrypt content
 * */

use std::io;

use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
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
