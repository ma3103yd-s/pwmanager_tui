pub mod password;
pub mod pbes;
pub mod ui;

use crate::password::PasswordEntries;
use crate::password::{ModuleList, HOME_ENV};
use crate::ui::{run_app, ModuleUI};

use std::collections::HashMap;
use std::env;
use std::io::{self, Read, Write};

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
    //let mut arg_it = env::args();
    //arg_it.next();
    /*
    while let Some(arg) = arg_it.next() {
        match arg.as_ref() {
            "-decrypt" => {
                if let Some(file) = arg_it.next() {
                    if let Some(der_file) = arg_it.next() {
                        let mut pw = String::new();
                        io::stdin().read_line(&mut pw)?;
                        println!("Decrypting {} from {}", file, der_file);
                        decrypt_from_der(pw.trim(), &file, &der_file)?;

                        return Ok(());
                    }
                }
                println!("No files given");
                return Ok(());
            }
            _ => {
                println!("Invalid argument");
                return Ok(());
            }
        }
    }
    */

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
}
