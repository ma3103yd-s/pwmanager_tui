use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write;
use std::fs::File;
use std::io;

use rand::distributions::{Alphanumeric, Uniform};
use rand::rngs::ThreadRng;
use rand::seq::index::sample;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    fn generate_random_string(len: usize) -> String {
        let mut rng = thread_rng();
        let mut pw: String = (&mut rng)
            .sample_iter(Alphanumeric)
            .take(len)
            .map(char::from)
            .collect();
        let spec_char: u8 = rng.sample(Uniform::new(33, 47));
        let cap_char: u8 = rng.sample(Uniform::new(65, 91));
        let mut ind = sample(&mut rng, len, 2);
        pw.insert(ind.index(0), char::from(spec_char));
        pw.insert(ind.index(1), char::from(cap_char));
        return pw;
    }
    pub fn get(&self) -> &str {
        &*self.0
    }
}
