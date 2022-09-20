pub mod password;
pub mod ui;

use crate::password::PasswordEntries;
use crate::password::{ModuleList, HOME_ENV};
use crate::ui::{run_app, ModuleUI};
use std::io;

use std::env;
use std::fs::{self, File};
use std::path::PathBuf;

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
    let mut base_path = PathBuf::from(env::var(HOME_ENV)?);
    let mut file = env::var(HOME_ENV)?;
    base_path.push(".pwmanager");
    if (!(base_path.try_exists()?)) {
        fs::create_dir(&base_path)?;
    }
    base_path.push("General.json");
    let mut mod_list = ModuleList::get_module_files()?;
    if let Err(_) = File::open(&base_path) {
        let et = PasswordEntries::new();
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
