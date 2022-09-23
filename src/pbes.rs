/*
 * Proecedure. Generate a hash with Argon2 crate of length 32
 * Serialize it and place in a file of some format.
 * Encrypt the content using ChaChaPoly AEAD.
 * Deserialize the Argon2 struct from the file and decrypt content
 * */

use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng},
    ChaCha20Poly1305, Nonce, Payload,
};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

pub struct Parameters<'a> {
    pub kdf: Argon2<'a>,
    pub encryption: Encryption,
}

pub struct EncryptionScheme<'a>(Parameters);

struct Encryption {
    val: ChaCha20Poly1305,
    nonce: Nonce,
}

impl<'a> EncryptionScheme<'a> {
    pub fn encrypt(&self, password: impl AsRef<[u8]>, plaintext: &[u8], aad: &[u8]) {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password, &salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(password_hash.as_bytes())?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let payload = Payload {
            msg: plaintext,
            aad: file,
        };
        let encrypted_content = cipher.encrypt(&nonce, payload)?;
    }
}
