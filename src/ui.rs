use std::borrow::Borrow;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Spans},
    widgets::*,
    Frame, Terminal,
};

use crate::password::{
    decrypt_from_der, read_from_file, ModuleList, Password, PasswordEntries, HOME_ENV,
};

pub struct ModuleUI<'a> {
    module_list: ModuleList<'a>,
    state: ListState,
    table_state: TableState,
    mode: PasswordMode,
    display_module: bool,
    input_string: String,
    module_index: Option<usize>,
    selection: Selection,
}
#[derive(PartialEq, Eq)]
enum PasswordMode {
    PasswordEntered,
    PasswordEntering,
    NoPassword,
}
enum Selection {
    Modules,
    Passwords,
}

impl<'a> ModuleUI<'a> {
    pub fn new(module_list: ModuleList<'a>) -> Self {
        Self {
            module_list,
            state: ListState::default(),
            table_state: TableState::default(),
            mode: PasswordMode::NoPassword,
            display_module: false,
            input_string: String::new(),
            module_index: None,
            selection: Selection::Modules,
        }
    }

    pub fn next_password(&mut self) {
        if let Some(i) = self.state.selected() {
            match self.module_list.modules.get(i).and_then(|x| x.2.as_ref()) {
                Some(entries) => {
                    let table_index = match self.table_state.selected() {
                        Some(_table_index) => {
                            if _table_index >= entries.len() - 1 {
                                0
                            } else {
                                i + 1
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
        if let Some(i) = self.state.selected() {
            match self.module_list.modules.get(i).and_then(|x| x.2.as_ref()) {
                Some(entries) => {
                    let table_index = match self.table_state.selected() {
                        Some(_table_index) => {
                            if _table_index == 0 {
                                entries.len() - 1
                            } else {
                                i - 1
                            }
                        }
                        None => 0,
                    };
                    self.state.select(Some(table_index));
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

    // Select the previous item. This will not be reflected until the widget is drawn in the
    // `Terminal::draw` callback using `Frame::render_stateful_widget`.
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

fn draw_module_list<B: Backend>(f: &mut Frame<B>, area: Rect, app: &mut ModuleUI) {
    let block = Block::default().title("Modules").borders(Borders::ALL);

    let items: Vec<ListItem> = app
        .module_list
        .modules
        .iter()
        .map(|(name, _, _)| ListItem::new(name.as_ref()))
        .enumerate()
        .map(|(i, l)| {
            let style = match app.module_index {
                Some(index) => {
                    if i == index {
                        if let Some(_) = app.module_list.modules.get(i).and_then(|x| x.2.as_ref()) {
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

fn draw_password_prompt<B: Backend>(f: &mut Frame<B>, area: Rect, app: &mut ModuleUI) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints([Constraint::Length(2), Constraint::Length(3)].as_ref())
        .split(area);
    let text = "Type in your password to unlock";
    let paragraph = Paragraph::new(Span::styled(
        text,
        Style::default().add_modifier(Modifier::SLOW_BLINK),
    ));
    let block = Block::default().title("Prompt").borders(Borders::ALL);
    f.render_widget(block, area);
    f.render_widget(paragraph, chunks[0]);
    let input = Paragraph::new(app.input_string.as_ref())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::all()).title("Input"));
    f.render_widget(Clear, chunks[1]);
    f.render_widget(input, chunks[1]);

    if app.mode == PasswordMode::PasswordEntering {
        f.set_cursor(chunks[1].x + app.input_string.len() as u16, chunks[1].y + 1)
    }
}

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

fn draw_module_selected<B: Backend>(f: &mut Frame<B>, area: Rect, app: &mut ModuleUI) {
    let block = Block::default().title("Passwords").borders(Borders::ALL);
    if let Some(v) = app
        .module_index
        .and_then(|i| app.module_list.modules.get_mut(i))
    {
        if v.2.is_none() {
            let mut base_path = PathBuf::from(env::var(HOME_ENV).unwrap());
            base_path.push(".pwmanager");
            if (!(base_path.try_exists().is_ok())) {
                fs::create_dir(&base_path).expect("Failed to create directory");
            }
            if let Some(der_file) = &v.1 {
                match app.mode {
                    PasswordMode::PasswordEntered => {
                        let path_str = base_path.to_string_lossy();
                        let f_str: &str = der_file.borrow();
                        let f_name = Path::new(f_str).file_stem().unwrap().to_string_lossy();
                        let js_file = format!("{}/{}.json", path_str, f_name);
                        //                        decrypt_from_der(&app.input_string, &js_file, &der_file)
                        //                            .expect(&format!("Failed to decrypt files {}:{}", js_file, der_file));

                        v.2 = decrypt_from_der(&app.input_string, &js_file, &der_file)
                            .ok()
                            .and_then(|_| read_from_file(Some(&js_file)).ok());
                        app.input_string = String::new();
                        app.mode = PasswordMode::NoPassword;
                    }
                    PasswordMode::NoPassword => {
                        app.mode = PasswordMode::PasswordEntering;
                    }
                    _ => {}
                }
            } else {
                let f_name: &str = v.0.borrow();
                let file = base_path.join(format!("{}.json", f_name));
                let file = file.to_string_lossy();

                v.2 = read_from_file(Some(file.borrow())).ok();
            }
        }
    }
    let entries: Option<Vec<Row>> = app
        .module_index
        .and_then(|i| app.module_list.modules.get(i))
        .and_then(|entry| {
            entry.2.as_ref().and_then(|x| {
                Some(
                    x.iter()
                        .map(|(k, v)| Row::new(vec![k.borrow(), v.0.borrow()]))
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
            .block(Block::default().title("Passwords"))
            .widths(&[Constraint::Length(20), Constraint::Length(64)])
            .column_spacing(1)
            .highlight_style(Style::default().add_modifier(Modifier::SLOW_BLINK));
        f.render_stateful_widget(table, area, &mut app.table_state);
    }
}

pub fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: ModuleUI) -> std::io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &mut app))?;
        if let Event::Key(key) = event::read()? {
            match app.mode {
                PasswordMode::NoPassword => match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Down => match app.selection {
                        Selection::Modules => app.next(),
                        Selection::Passwords => app.next_password(),
                    },
                    KeyCode::Up => match app.selection {
                        Selection::Modules => app.previous(),
                        Selection::Passwords => app.previous_password(),
                    },
                    KeyCode::Enter => {
                        app.display_module = true;
                        app.module_index = app.state.selected();
                    }
                    _ => {}
                },
                PasswordMode::PasswordEntering => match key.code {
                    KeyCode::Char(c) => app.input_string.push(c),
                    KeyCode::Enter => {
                        app.mode = PasswordMode::PasswordEntered;
                    }

                    KeyCode::Backspace => {
                        app.input_string.pop();
                    }
                    _ => {}
                },
                _ => app.mode = PasswordMode::NoPassword,
            }
        }
    }
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut ModuleUI) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .margin(2)
        .constraints([Constraint::Length(10), Constraint::Length(10)].as_ref())
        .split(f.size());
    let area = centered_rect(50, 30, f.size());
    if app.display_module == true {
        draw_module_selected(f, chunks[1], app);
    }
    draw_module_list(f, chunks[0], app);
    if app.mode == PasswordMode::PasswordEntering {
        draw_password_prompt(f, area, app);
    }
}
