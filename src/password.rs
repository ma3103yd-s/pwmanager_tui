use rand::distributions::{Alphanumeric, Uniform};
use rand::rngs::OsRng;
use rand::rngs::ThreadRng;
use rand::seq::index::{self, sample};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;

use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use der::Document;
use pkcs5::der::{Decode, Encode};
use pkcs5::{pbes2::Parameters, EncryptionScheme};
use std::ffi::OsStr;

pub type PasswordEntries<'a> = HashMap<Cow<'a, str>, Password<'a>>;

pub fn add_password_32<'a>(
    entries: &mut PasswordEntries<'a>,
    name: &'a str,
) -> Option<Password<'a>> {
    let pw: Password = Password::new_password32();
    entries.insert(Cow::from(name), pw)
}

pub fn add_password_64<'a>(
    entries: &mut PasswordEntries<'a>,
    name: &'a str,
) -> Option<Password<'a>> {
    let pw: Password = Password::new_password64();
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

pub struct ModuleList<'a> {
    pub modules: Vec<(
        Cow<'a, str>,
        Option<Cow<'a, str>>,
        Option<PasswordEntries<'a>>,
    )>,
}

impl ModuleList<'_> {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    pub fn create_module(name: &str, entries: &PasswordEntries) -> io::Result<()> {
        let file_name = format!("{}.json", name);
        let f = match File::open(&file_name) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Module already exists.",
            )),
            Err(e) => {
                if e.kind() == io::ErrorKind::NotFound {
                    File::create(&file_name)
                } else {
                    Err(e)
                }
            }
        }?;
        serde_json::to_writer(f, entries)?;
        Ok(())
    }

    pub fn get_module_files() -> Result<Self, Box<dyn std::error::Error>> {
        let mut mod_list = Self::new();
        let env_var = if cfg!(windows) {
            "USERPROFILE"
        } else if cfg!(unix) {
            "HOME"
        } else {
            "NONEXISTANT"
        };

        let mut base_path = PathBuf::from(env::var(env_var)?);
        base_path.push(".pwmanager");
        if (!(base_path.try_exists()?)) {
            fs::create_dir(base_path)?;
            return Ok(mod_list);
        }
        let mut entry_iter = base_path.read_dir()?;
        for entry in entry_iter.by_ref() {
            if let Ok(p) = entry {
                let path = p.path();
                let mod_name = path
                    .file_name()
                    .and_then(|s| Path::new(s).file_stem())
                    .unwrap()
                    .to_string_lossy();
                let extension = path.extension().unwrap();
                if extension == "json" {
                    let der_path = path.with_extension("der");
                    if der_path.is_file() {
                        mod_list.modules.push((
                            Cow::from(mod_name.into_owned()),
                            Some(Cow::from(der_path.to_string_lossy().into_owned())),
                            None,
                        ));
                    } else {
                        mod_list
                            .modules
                            .push((Cow::from(mod_name.into_owned()), None, None))
                    }
                }
            }
        }
        Ok(mod_list)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Password<'a>(Cow<'a, str>);

impl Password<'_> {
    pub fn new_password32() -> Self {
        Self(Cow::from(Self::generate_random_string(32)))
    }
    pub fn new_password64() -> Self {
        Self(Cow::from(Self::generate_random_string(64)))
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

    pub fn encrypt_with_password<'a>(
        &self,
        file: &str,
        salt: &'a [u8],
        iv: &'a [u8; 16],
    ) -> Result<EncryptionScheme<'a>, Box<dyn std::error::Error>> {
        encrypt_file(self.get(), file, salt, iv)
    }

    pub fn encrypt_from_input(file: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        password_encrypt_file(&input, file)?;
        Ok(())
    }

    pub fn decrypt_from_input(
        file: &str,
        der_file: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        decrypt_from_der(&input, file, der_file)?;
        Ok(())
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
    let mut f = File::create(file)?;
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
    let mut f = File::create(file)?;
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
