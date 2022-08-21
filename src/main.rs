pub mod password;
use std::io;

use crate::password::{add_password_32, read_from_file, write_to_file, Password, PasswordEntries};
use std::borrow::Cow;

fn main() -> io::Result<()> {
    let mut pw_e = read_from_file(None)?;
    println!(
        "Deserialized Amazon password is {}",
        pw_e.get("Amazon").unwrap().get()
    );
    add_password_32(&mut pw_e, "Google");
    add_password_32(&mut pw_e, "Runelite");
    write_to_file(None, &pw_e)?;
    Ok(())
}
