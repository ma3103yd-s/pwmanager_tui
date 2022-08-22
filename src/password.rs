use rand::distributions::{Alphanumeric, Uniform};
use rand::rngs::OsRng;
use rand::rngs::ThreadRng;
use rand::seq::index::{self, sample};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

use std::fs::File;
use std::io;
use std::io::{Read, Write};

use der::Document;
use pkcs5::der::{Decode, Encode};
use pkcs5::{pbes2::Parameters, EncryptionScheme};

pub type PasswordEntries<'a> = HashMap<Cow<'a, str>, Password<'a>>;

pub fn add_password_32<'a>(
    entries: &mut PasswordEntries<'a>,
    name: &'a str,
) -> Option<Password<'a>> {
    let pw: Password = Password::new_password32();
    entries.insert(Cow::from(name), pw)
}

pub fn write_to_file(file: Option<&str>, entries: &PasswordEntries) -> io::Result<()> {
    let f = File::create(file.unwrap_or("passwords.json"))?;
    serde_json::to_writer(f, entries)?;
    Ok(())
}

pub fn read_from_file(file: Option<&str>) -> io::Result<PasswordEntries> {
    let file = File::open(file.unwrap_or("passwords.json"))?;
    let pw_entry: PasswordEntries = serde_json::from_reader(&file)?;
    return Ok(pw_entry);
}

#[derive(Serialize, Deserialize)]
pub struct Password<'a>(Cow<'a, str>);

impl Password<'_> {
    pub fn new_password32() -> Self {
        Self(Cow::from(Self::generate_random_string(32)))
    }
    pub fn generate_random_string(len: usize) -> String {
        let mut rng = thread_rng();
        let spec_char: u8 = rng.sample(Uniform::new(33, 47));
        let cap_char: u8 = rng.sample(Uniform::new(65, 91));
        let ind = sample(&mut rng, len, 2);
        let pw: String = (&mut rng)
            .sample_iter(Alphanumeric)
            .take(len)
            .enumerate()
            .map(|(i, c)| {
                if (i == ind.index(0)) {
                    spec_char
                } else if (i == ind.index(1)) {
                    cap_char
                } else {
                    c
                }
            })
            .map(char::from)
            .collect();

        return pw;
    }
    pub fn get(&self) -> &str {
        &*self.0
    }
}

pub fn encrypt_file<'a>(
    password: &str,
    file: &str,
    salt: &'a [u8],
    iv: &'a [u8; 16],
) -> Result<EncryptionScheme<'a>, Box<dyn std::error::Error>> {
    let mut f = File::open(file)?;
    let mut content = Vec::new();
    f.read_to_end(&mut content)?;
    let iterations = 310_000;
    let params = Parameters::pbkdf2_sha256_aes256cbc(iterations, &salt, iv)
        .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;
    let encrypt_scheme = EncryptionScheme::Pbes2(params);
    let encrypted_content = encrypt_scheme
        .encrypt(password, &content)
        .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;
    let mut f = File::create("encrypted.txt")?;
    f.write_all(&encrypted_content)?;
    Ok(encrypt_scheme)
}

pub fn save_to_der<'a>(
    file: &str,
    ec_scheme: &EncryptionScheme<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut content: [u8; 128] = [0; 128];
    let ec_content = ec_scheme
        .encode_to_slice(&mut content)
        .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;
    let doc = Document::from_der(ec_content)?;
    doc.write_der_file("password.der")?;

    Ok(())
}

pub fn decrypt_file<'a>(
    password: &str,
    file: &str,
    ec_scheme: &EncryptionScheme<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut encrypted_content: Vec<u8> = Vec::new();
    let mut f = File::open(file)?;
    f.read_to_end(&mut encrypted_content)?;
    let decrypted_content = ec_scheme
        .decrypt(password, &encrypted_content)
        .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;

    let content = std::str::from_utf8(&decrypted_content)?;
    println!("Decrypted content is {}", content);
    let mut f = File::create("decrypted.txt")?;
    f.write_all(&decrypted_content)?;
    Ok(())
}

pub fn password_encrypt_file(password: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let salt = Password::generate_random_string(8);
    let iv_string = Password::generate_random_string(16);
    println!("iv string is {:?}", iv_string);
    println!("iv string is {:?}", iv_string.as_bytes());
    let iv: &[u8; 16] = iv_string.as_bytes().try_into().unwrap();
    let ec_scheme = encrypt_file(password, file, &salt.as_bytes(), iv)?;
    save_to_der("password.der", &ec_scheme)?;
    Ok(())
}

pub fn decrypt_from_der(
    password: &str,
    file: &str,
    der_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let doc = Document::read_der_file(der_file)?;
    let ec_scheme: EncryptionScheme = doc.decode_msg()?;

    //    let ec_scheme = EncryptionScheme::from_der(&content)
    //        .map_err(|E| io::Error::new(io::ErrorKind::Other, E.to_string()))?;
    decrypt_file(password, file, &ec_scheme)
}
