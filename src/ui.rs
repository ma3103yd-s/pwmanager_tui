use std::borrow::{Borrow, Cow};
use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans, Text},
    widgets::*,
    Frame, Terminal,
};

use crate::password::{read_from_file, ModuleList, Password, PasswordEntries, HOME_ENV};

use crate::pbes::EncryptionScheme;
use ron;

/* Struct to hold UI data */
pub struct ModuleUI<'a> {
    module_list: ModuleList<'a>,
    state: ListState,
    table_state: TableState,
    table_key: Option<Cow<'a, str>>,
    display_module: bool,
    input_string: String,
    module_index: Option<usize>,
    selection: Selection,
    input_mode: InputMode,
    input_to: InputTo,
    passwords: HashMap<Cow<'a, str>, String>,
    ctx: Option<ClipboardContext>,
    display_error: bool,
    error_message: String,
}
/* Input Mode of the UI*/
#[derive(PartialEq, Eq)]
enum InputMode {
    Normal,
    Inputing,
}
/* The part of the UI we are inputing to*/
#[derive(PartialEq, Eq)]
enum InputTo {
    Nothing,
    Decrypt,
    Encrypt,
    Module,
    Password,
    Add,
}
/* Selection of module or password*/
enum Selection {
    Modules,
    Passwords,
}

/* Methods for the UI*/
impl<'a> ModuleUI<'a> {
    pub fn new(module_list: ModuleList<'a>) -> Self {
        Self {
            module_list,
            state: ListState::default(),
            table_state: TableState::default(),
            table_key: None,
            display_module: false,
            input_string: String::new(),
            module_index: None,
            selection: Selection::Modules,
            input_mode: InputMode::Normal,
            input_to: InputTo::Nothing,
            passwords: HashMap::new(),
            ctx: ClipboardProvider::new().ok(),
            display_error: false,
            error_message: String::new(),
        }
    }
    /* Implements selection of passwords*/
    pub fn next_password(&mut self) {
        if let Some(i) = self.module_index {
            match self.module_list.modules.get(i).and_then(|x| x.1.as_ref()) {
                Some(entries) => {
                    let table_index = match self.table_state.selected() {
                        Some(_table_index) => {
                            if _table_index >= entries.len() - 1 {
                                0
                            } else {
                                _table_index + 1
                            }
                        }
                        None => 0,
                    };
                    self.table_state.select(Some(table_index));
                }
                None => {}
            }
        }
    }

    pub fn previous_password(&mut self) {
        if let Some(i) = self.module_index {
            match self.module_list.modules.get(i).and_then(|x| x.1.as_ref()) {
                Some(entries) => {
                    let table_index = match self.table_state.selected() {
                        Some(_table_index) => {
                            if _table_index == 0 {
                                entries.len() - 1
                            } else {
                                _table_index - 1
                            }
                        }
                        None => 0,
                    };
                    self.table_state.select(Some(table_index));
                }
                None => {}
            }
        }
    }
    pub fn unselect_password(&mut self) {
        self.table_state.select(None);
    }

    fn set_items(&mut self, items: ModuleList<'a>) {
        self.module_list = items;
        self.state = ListState::default();
    }
    /* Implements selection of modules */
    pub fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.module_list.modules.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    // Select the previous item.
    pub fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.module_list.modules.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    // Unselect the currently selected item if any. The implementation of `ListState` makes
    // sure that the stored offset is also reset.
    pub fn unselect(&mut self) {
        self.state.select(None);
    }
}
/* Draw the list of modules */
fn draw_module_list<B: Backend>(f: &mut Frame<B>, area: Rect, app: &mut ModuleUI) {
    let block = Block::default().title("Modules").borders(Borders::ALL);

    let items: Vec<ListItem> = app
        .module_list
        .modules
        .iter()
        .map(|(name, _)| ListItem::new(name.as_ref()))
        .enumerate()
        .map(|(i, l)| {
            let style = match app.module_index {
                Some(index) => {
                    if i == index {
                        if let Some(_) = app.module_list.modules.get(i).and_then(|x| x.1.as_ref()) {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::Red)
                        }
                    } else {
                        Style::default().fg(Color::White)
                    }
                }
                None => Style::default().fg(Color::White),
            };
            l.style(style)
        })
        .collect();
    let list = List::new(items)
        .block(block)
        .style(Style::default().fg(Color::White))
        .highlight_symbol(">");
    f.render_stateful_widget(list, area, &mut app.state);
}
/* Draws the input prompt depending on what we are inputing to */
fn draw_input_prompt<B: Backend>(f: &mut Frame<B>, area: Rect, app: &mut ModuleUI) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([Constraint::Length(2), Constraint::Length(2)].as_ref())
        .split(area);
    let text = match app.input_to {
        InputTo::Decrypt => "Type in the password to decrypt module",
        InputTo::Encrypt => "Type in password to encrypt module with",
        InputTo::Module => "Type the name of the module",
        InputTo::Password => "Type in name/description of password",
        InputTo::Add => "Type name (Tab) password to import password",
        _ => "Something went wrong. Press q to exit",
    };
    let paragraph = Paragraph::new(Span::styled(
        text,
        Style::default().add_modifier(Modifier::SLOW_BLINK),
    ))
    .wrap(Wrap { trim: true });
    let block = Block::default().title("Prompt").borders(Borders::ALL);
    f.render_widget(Clear, area);
    f.render_widget(block, area);
    f.render_widget(paragraph, chunks[0]);
    // Need  to handle case of manual password differently since it needs two inputs
    if app.input_to == InputTo::Add {
        let input_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(15), Constraint::Length(20)].as_ref())
            .split(chunks[1]);
        let mut x_coord = 0_u16;
        let y_coord = input_chunks[0].y + 1;
        let mut iter = app.input_string.split_whitespace();
        let first_input = if let Some(first) = iter.next() {
            x_coord = input_chunks[0].x + first.len() as u16 + 1;
            Paragraph::new(first.as_ref())
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::all()).title("Name"))
        } else {
            x_coord = input_chunks[0].x + 1;
            Paragraph::new("")
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::all()).title("Name"))
        };

        let second_input = if let Some(second) = iter.next() {
            x_coord = input_chunks[1].x + second.len() as u16;
            Paragraph::new(second.get(1..).unwrap_or(""))
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::all()).title("Password"))
        } else {
            Paragraph::new("")
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().borders(Borders::all()).title("Password"))
        };
        f.render_widget(Clear, chunks[1]);
        f.render_widget(first_input, input_chunks[0]);
        f.render_widget(second_input, input_chunks[1]);
        f.set_cursor(x_coord, y_coord);
    } else {
        let input = Paragraph::new(app.input_string.as_ref())
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::all()).title("Input"));
        f.render_widget(input, chunks[1]);
        if app.input_mode == InputMode::Inputing {
            f.set_cursor(
                chunks[1].x + app.input_string.len() as u16 + 1,
                chunks[1].y + 1,
            )
        }
    }
}

/* Draws a centered rectangle on r with the given width and height in percentage */
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
/* Draws the list of commands */
fn draw_command_list<B: Backend>(f: &mut Frame<B>, area: Rect, app: &mut ModuleUI) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(1)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);
    let block = Block::default().title("Key Commands").borders(Borders::ALL);
    let style = Style::default().fg(Color::Blue);
    let text1 = vec![
        Spans::from(vec![
            Span::styled("g", style),
            Span::raw("(enerate): Generate new password"),
        ]),
        Spans::from(vec![
            Span::styled("a", style),
            Span::raw("(dd): Add password"),
        ]),
        Spans::from(vec![
            Span::styled("m", style),
            Span::raw("(odule): Create Module"),
        ]),
        Spans::from(vec![
            Span::styled("e", style),
            Span::raw("(ncrypt): Encrypt module"),
        ]),
        Spans::from(vec![
            Span::styled("d", style),
            Span::raw("(elete): Delete selected password"),
        ]),
        Spans::from(vec![
            Span::styled("c", style),
            Span::raw("(opy): Copy selected password to clipboard"),
        ]),
    ];

    let text2 = vec![
        Spans::from(vec![
            Span::styled("[Esc]", style),
            Span::raw(": Exit input"),
        ]),
        Spans::from(vec![
            Span::styled("←", style),
            Span::raw(": Module Selection"),
        ]),
        Spans::from(vec![
            Span::styled("→", style),
            Span::raw(": Password Selection"),
        ]),
        Spans::from(vec![Span::styled("↑", style), Span::raw(": Scroll up")]),
        Spans::from(vec![Span::styled("↓", style), Span::raw(": Scroll Down")]),
        Spans::from(vec![
            Span::styled("[Enter]", style),
            Span::raw(": Select Module"),
        ]),
        Spans::from(vec![
            Span::styled("q", style),
            Span::raw("(uit): Quit program"),
        ]),
    ];

    let pg1 = Paragraph::new(text1)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    let pg2 = Paragraph::new(text2)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    f.render_widget(block, area);
    f.render_widget(pg1, chunks[0]);
    f.render_widget(pg2, chunks[1]);
}
/* Reads an unencrypted module from the corresponding file */
pub fn read_unencrypted_module<'a>(
    m: &mut (Cow<'a, str>, Option<PasswordEntries<'a>>),
) -> Result<(), Box<dyn std::error::Error>> {
    let mut base_path = PathBuf::from(env::var(HOME_ENV)?);
    base_path.push(".pwmanager");
    let f_name: &str = m.0.borrow();
    let file = base_path.join(format!("{}.json", f_name));
    let file = file.to_string_lossy();

    m.1 = Some(read_from_file(Some(file.borrow()))?);
    Ok(())
}
/* Reads a module from an encrypted file.*/
pub fn read_encrypted_module<'a>(
    list: &mut HashMap<Cow<'a, str>, EncryptionScheme>,
    password: &str,
    m: &mut (Cow<'a, str>, Option<PasswordEntries<'a>>),
) -> Result<(), Box<dyn std::error::Error>> {
    let mut base_path = PathBuf::from(env::var(HOME_ENV)?);
    base_path.push(".pwmanager");
    let f_name: &str = m.0.borrow();
    let file = base_path.join(format!("{}.json", f_name));
    let file = file.to_string_lossy();

    if let Some(ec) = list.get(&m.0) {
        ec.decrypt_file(password, &file)?;
        let et = read_from_file(Some(&file))?;
        m.1 = Some(et);
    }
    Ok(())
}
/* Displays the passwords of the selected module */
fn draw_module_selected<B: Backend>(f: &mut Frame<B>, area: Rect, app: &mut ModuleUI) {
    let block = Block::default().title("Passwords").borders(Borders::ALL);
    let entries: Option<Vec<Row>> = app
        .module_index
        .and_then(|i| app.module_list.modules.get(i))
        .and_then(|entry| {
            entry.1.as_ref().and_then(|x| {
                Some(
                    x.iter()
                        .enumerate()
                        .map(|(i, (k, v))| {
                            if let Some(s) = app.table_state.selected() {
                                if i == s {
                                    app.table_key = Some(k.to_owned());
                                }
                            }
                            Row::new(vec![k.borrow(), v.0.borrow()])
                        })
                        .collect(),
                )
            })
        });

    if let Some(rows) = entries {
        let table = Table::new(rows)
            .style(Style::default().fg(Color::White))
            .header(
                Row::new(vec!["Name", "Password"])
                    .style(Style::default().fg(Color::Yellow))
                    .bottom_margin(1),
            )
            .block(block)
            .widths(&[Constraint::Length(20), Constraint::Length(64)])
            .column_spacing(2)
            .highlight_style(Style::default().add_modifier(Modifier::RAPID_BLINK))
            .highlight_symbol("►");
        f.render_stateful_widget(table, area, &mut app.table_state);
    }
}

/* Encrypts all files that were decrypted. Resets all inputs, passwords and modules to prevent
 * leakage */
pub fn clean_up(app: &mut ModuleUI) -> Result<(), Box<dyn std::error::Error>> {
    let base_path = PathBuf::from(env::var(HOME_ENV)?);
    for row in app.module_list.modules.iter_mut() {
        let name = row.0.borrow();
        if let Some(et) = row.1.as_mut() {
            ModuleList::write_module(name, et)?;
            if let Some(ec) = app.module_list.encryptions.get(&row.0) {
                if let Some(pw) = app.passwords.get(name) {
                    let file_name = base_path.join(format!(".pwmanager/{}.json", name));
                    let file_name = file_name.to_string_lossy();
                    ec.encrypt_file(pw, &file_name)?;
                }
            }
        }
    }
    let mut enc_file = File::create(base_path.join(".pwmanager/encryptions.ron"))?;
    ron::ser::to_writer(enc_file, &app.module_list.encryptions)?;

    app.input_string = String::new();
    app.passwords = HashMap::new();
    app.module_list.modules = Vec::new();
    app.module_list.encryptions = HashMap::new();
    Ok(())
}

/* Popup for displaying errors.*/
pub fn display_error<B: Backend>(f: &mut Frame<B>, area: Rect, message: &str) {
    let p = Paragraph::new(Text::styled(message, Style::default().fg(Color::White)))
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::LightRed))
        .block(Block::default().title("Error").borders(Borders::ALL));
    f.render_widget(Clear, area);
    f.render_widget(p, area);
}
/* Runs the app */
pub fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: ModuleUI,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        terminal.draw(|f| ui(f, &mut app)).map_err(|e| {
            clean_up(&mut app).expect("Failed to clean up on error");
            e
        })?;

        if let Event::Key(key) = event::read()? {
            match app.input_mode {
                InputMode::Normal => match key.code {
                    KeyCode::Char('q') => return clean_up(&mut app),
                    KeyCode::Down => match app.selection {
                        Selection::Modules => app.next(),
                        Selection::Passwords => app.next_password(),
                    },
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_to = InputTo::Nothing;
                        app.display_error = false;
                    }
                    KeyCode::Up => match app.selection {
                        Selection::Modules => app.previous(),
                        Selection::Passwords => app.previous_password(),
                    },
                    KeyCode::Enter => {
                        app.module_index = app.state.selected();
                        if let Some(m) = app
                            .module_index
                            .and_then(|i| app.module_list.modules.get_mut(i))
                        {
                            if m.1.is_some() {
                                app.display_module = true;
                                continue;
                            }

                            match app.module_list.encryptions.get(&m.0) {
                                Some(_) => {
                                    app.input_mode = InputMode::Inputing;
                                    app.input_to = InputTo::Decrypt;
                                }
                                None => {
                                    if let Err(e) = read_unencrypted_module(m) {
                                        app.display_error = true;
                                        app.error_message = e.to_string();
                                    } else {
                                        app.display_module = true;
                                    }
                                }
                            }
                        }
                    }
                    KeyCode::Char('g') => {
                        app.input_mode = InputMode::Inputing;
                        app.input_to = InputTo::Password;
                    }
                    KeyCode::Char('m') => {
                        app.input_mode = InputMode::Inputing;
                        app.input_to = InputTo::Module;
                    }
                    KeyCode::Char('e') => {
                        app.input_mode = InputMode::Inputing;
                        app.input_to = InputTo::Encrypt;
                    }
                    KeyCode::Right => {
                        app.selection = Selection::Passwords;
                    }
                    KeyCode::Left => app.selection = Selection::Modules,
                    KeyCode::Char('a') => {
                        app.input_mode = InputMode::Inputing;
                        app.input_to = InputTo::Add;
                    }
                    KeyCode::Char('d') => {
                        if let Some(m) = app
                            .module_index
                            .and_then(|i| app.module_list.modules.get_mut(i))
                        {
                            if let Some(k) = &app.table_key {
                                if let Some(et) = m.1.as_mut() {
                                    et.remove(k);
                                }
                            }
                        } else {
                            app.display_error = true;
                            app.error_message = "No selection found".to_owned();
                        }
                    }
                    KeyCode::Char('c') => {
                        if let Some(k) = &app.table_key {
                            if let Some(ctx) = &mut app.ctx {
                                if let Some(et) = app
                                    .module_index
                                    .and_then(|i| app.module_list.modules.get(i))
                                    .and_then(|m| m.1.as_ref())
                                {
                                    let pw = et.get(k).unwrap();
                                    ctx.set_contents(pw.get().to_owned())?;
                                }
                            } else {
                                app.display_error = true;
                                app.error_message = "Error copying from clipboard".to_owned();
                            }
                        }
                    }
                    _ => {}
                },
                InputMode::Inputing => match key.code {
                    KeyCode::Char(c) => app.input_string.push(c),
                    KeyCode::Tab => {
                        app.input_string.push(' ');
                        app.input_string.push('c')
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                        app.input_to = InputTo::Nothing;
                        app.display_error = false;
                    }
                    KeyCode::Enter => {
                        app.input_mode = InputMode::Normal;
                        match app.input_to {
                            InputTo::Password => {
                                if let Some(m) = app
                                    .module_index
                                    .and_then(|i| app.module_list.modules.get_mut(i))
                                {
                                    let pw = Password::new_password32();
                                    let entry = m.1.get_or_insert(PasswordEntries::new());
                                    entry.insert(Cow::Owned(app.input_string.clone()), pw);
                                    app.input_string = String::new();
                                    app.input_to = InputTo::Nothing;
                                } else {
                                    app.display_error = true;
                                    app.error_message = "No module selected".to_owned();
                                }
                            }
                            InputTo::Add => {
                                if let Some(m) = app
                                    .module_index
                                    .and_then(|i| app.module_list.modules.get_mut(i))
                                {
                                    let mut iter = app.input_string.split_whitespace();
                                    if let Some(name) = iter.next() {
                                        if let Some(pw) = iter.next() {
                                            let pw = pw.get(1..).unwrap_or("");
                                            let password = Password::new_from(pw);
                                            let entry = m.1.get_or_insert(PasswordEntries::new());
                                            entry.insert(Cow::Owned(name.to_owned()), password);
                                            app.input_string = String::new();
                                            app.input_to = InputTo::Nothing;
                                        } else {
                                            app.display_error = true;
                                            app.error_message = "No password entered".to_owned();
                                        }
                                    } else {
                                        app.display_error = true;
                                        app.error_message = "No name entered".to_owned();
                                    }
                                }
                            }
                            InputTo::Decrypt => {
                                if let Some(m) = app
                                    .module_index
                                    .and_then(|i| app.module_list.modules.get_mut(i))
                                {
                                    if let Err(e) = read_encrypted_module(
                                        &mut app.module_list.encryptions,
                                        &app.input_string,
                                        m,
                                    ) {
                                        app.display_error = true;
                                        app.error_message = e.to_string();

                                        app.error_message
                                            .push_str("\nMost likely wrong password\n");
                                    } else {
                                        app.display_module = true;
                                        app.passwords
                                            .insert(m.0.to_owned(), app.input_string.clone());
                                    }
                                    app.input_to = InputTo::Nothing;
                                    app.input_mode = InputMode::Normal;
                                    app.input_string = String::new();
                                }
                            }
                            InputTo::Module => {
                                let entries = PasswordEntries::new();
                                app.module_list.add_module(&app.input_string, entries)?;
                                app.input_string = String::new();
                                app.input_to = InputTo::Nothing;
                            }
                            InputTo::Encrypt => {
                                if let Some(m) = app
                                    .module_index
                                    .and_then(|i| app.module_list.modules.get(i))
                                {
                                    if (app.input_string.is_empty()) {
                                        app.display_error = true;
                                        app.error_message = "Please enter a password".to_owned();
                                        continue;
                                    }
                                    let base_path = env::var(HOME_ENV)?;
                                    let name: &str = m.0.borrow();
                                    let file = format!("{}\\.pwmanager\\{}.json", base_path, name);
                                    let ec = EncryptionScheme::default();

                                    //create_and_save_to_der(&der_file)?;
                                    //m.1 = Some(Cow::Owned(der_file.to_owned()));
                                    app.module_list.encryptions.insert(m.0.to_owned(), ec);
                                    app.passwords
                                        .insert(m.0.to_owned(), app.input_string.clone());
                                    app.input_string = String::new();
                                    app.input_to = InputTo::Nothing;
                                } else {
                                    app.display_error = true;
                                    app.error_message = "No module selected".to_owned();
                                }
                            }
                            _ => {}
                        }
                    }

                    KeyCode::Backspace => {
                        app.input_string.pop();
                    }
                    _ => {}
                },
            }
        }
    }
}

/* Calls the different UI functions and provides layout*/
fn ui<B: Backend>(f: &mut Frame<B>, app: &mut ModuleUI) {
    let mod_size: u16 = app.module_list.modules.len() as u16;
    let command_size: u16 = 7;
    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(command_size + 2)])
        .split(f.size());
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(2)
        .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
        .split(v_chunks[0]);

    let area = centered_rect(60, 20, f.size());

    if app.display_module == true {
        draw_module_selected(f, chunks[1], app);
    }
    draw_module_list(f, chunks[0], app);
    draw_command_list(f, v_chunks[1], app);

    if app.input_mode == InputMode::Inputing {
        draw_input_prompt(f, area, app);
    }
    if app.display_error == true {
        display_error(f, area, &app.error_message);
    }
}
