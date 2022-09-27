pub mod password;
pub mod pbes;
pub mod ui;

use crate::password::PasswordEntries;
use crate::password::{ModuleList, HOME_ENV};
use crate::ui::{run_app, ModuleUI};
use std::collections::HashMap;
use std::io::{self, Read, Write};

use std::env;
use std::fs::{self, File};
use std::path::PathBuf;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use password::{decrypt_file, decrypt_from_file, encrypt_file, save_to_file};
use pbes::EncryptionScheme;
use tui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};

use ron::ser::to_writer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut base_path = PathBuf::from(env::var(HOME_ENV)?);
    let mut file = env::var(HOME_ENV)?;
    base_path.push(".pwmanager");
    if (!(base_path.try_exists()?)) {
        fs::create_dir(&base_path)?;
    }
    let enc_file = base_path.join("encryptions.ron");
    let mut enc_file = File::open(&enc_file).ok();
    let mut content = enc_file.as_ref().map(|_| Vec::new());
    if let Some(enc) = enc_file.as_mut() {
        enc.read_to_end(content.as_mut().unwrap())?;
        drop(enc);
    }
    base_path.push("General.json");
    let mut mod_list = ModuleList::get_module_list(content.as_ref())?;
    if let Err(_) = File::open(&base_path) {
        println!("Base path is {:?}", base_path);
        let et = PasswordEntries::new();
        ModuleList::write_module("General", &et)?;
        mod_list.add_module("General", et)?;
    }
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let app = ModuleUI::new(mod_list);

    // create app and run it

    run_app(&mut terminal, app)?;

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())

    //let mut hm: HashMap<String, EncryptionScheme> = HashMap::new();
    //let f = File::create("src/encryptions.ron")?;
    //let ec_1 = encrypt_file("password", "src/test.txt")?;
    //let ec_2 = encrypt_file("password", "src/test2.txt")?;
    //hm.insert("test".to_owned(), ec_1);
    //hm.insert("test2".to_owned(), ec_2);
    //ron::ser::to_writer(f, &hm)?;
    //save_to_file("src/ec_scheme.txt", &ec)?;
    //decrypt_from_file("password", "src/test.txt", "src/ec_scheme.txt")?;
}

fn test_argon() -> Result<(), Box<dyn std::error::Error>> {
    let ec = encrypt_file("password", "src/test.txt")?;
    decrypt_file("password", "src/test.txt", &ec)?;
    Ok(())
}

fn test_serialize() -> Result<(), Box<dyn std::error::Error>> {
    let f = File::create("src/ec_scheme.txt")?;
    let ec = encrypt_file("password", "src/test.txt")?;
    to_writer(f, &ec)?;
    decrypt_file("password", "src/test.txt", &ec)?;
    Ok(())
}

fn test_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::open("src/ec_scheme.txt")?;
    let mut content: Vec<u8> = Vec::new();
    f.read_to_end(&mut content)?;
    let ec: EncryptionScheme = ron::de::from_bytes(&content)?;
    println!("Salt string is {}", ec.salt.as_str());
    println!("Nonce is {:?}", ec.nonce);
    Ok(())
}
