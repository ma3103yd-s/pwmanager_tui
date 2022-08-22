pub mod password;
use std::io::{self, Read, Write};

use crate::password::decrypt_from_der;
use crate::password::{add_password_32, read_from_file, write_to_file, Password, PasswordEntries};
use rand::rngs::OsRng;
use std::borrow::Cow;
use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut pw_e = read_from_file(None)?;
    println!(
        "Deserialized Amazon password is {}",
        pw_e.get("Amazon").unwrap().get()
    );
    add_password_32(&mut pw_e, "Google");
    add_password_32(&mut pw_e, "Runelite");
    write_to_file(None, &pw_e)?;
    //password_encrypt_file("Hunter2", "passwords.json")?;
    decrypt_from_der("Hunter2", "encrypted.txt", "password.der")?;
    Ok(())
}
