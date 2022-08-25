pub mod password;
pub mod ui;
use std::io::{self, Read, Write};

use crate::password::decrypt_from_der;
use crate::password::ModuleList;
use crate::password::{add_password_32, read_from_file, write_to_file, Password, PasswordEntries};
use crate::ui::{run_app, ModuleUI};

use rand::rngs::OsRng;
use std::borrow::Cow;
use std::fs::File;

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
    //    let mut pw_e = read_from_file(None)?;
    //    println!(
    //        "Deserialized Amazon password is {}",
    //        pw_e.get("Amazon").unwrap().get()
    //    );
    //    add_password_32(&mut pw_e, "Google");
    //    add_password_32(&mut pw_e, "Runelite");
    //    write_to_file(None, &pw_e)?;
    //Password::encrypt_from_input("passwords.json")?;
    //Password::decrypt_from_input("passwords.json", "password.der")?;
    let mut module_test = PasswordEntries::new();
    add_password_32(&mut module_test, "Facebook");
    add_password_32(&mut module_test, "Amazon");
    let mod_list = ModuleList::get_module_files()?;
    let mut app = ModuleUI::new(mod_list);
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let res = run_app(&mut terminal, app);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err)
    }

    Ok(())

    //println!("Module list contains {:?}", mod_list.modules);
}
