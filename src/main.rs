pub mod password;
pub mod ui;
use std::io::{self, BufRead, Read, Write};

use crate::password::decrypt_from_der;
use crate::password::{add_password_32, read_from_file, write_to_file, Password, PasswordEntries};
use crate::password::{ModuleList, HOME_ENV};
use crate::ui::{run_app, ModuleUI};

use password::encrypt_from_der;
use password::{create_and_save_to_der, password_encrypt_file};
use rand::rngs::OsRng;
use std::borrow::Cow;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = env::var(HOME_ENV)?;
    file.push_str("/.pwmanager/General.json");
    let mut mod_list = ModuleList::get_module_files()?;
    if let Err(_) = File::open(&file) {
        let et = PasswordEntries::new();
        mod_list.add_module("General", et)?;
    }
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = ModuleUI::new(mod_list);

    // create app and run it

    let res = run_app(&mut terminal, app)?;

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
