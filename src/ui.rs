use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use tui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::*,
    Frame, Terminal,
};

use crate::password::{ModuleList, Password, PasswordEntries, decrypt_from_der};

pub struct ModuleUI<'a> {
    module_list: ModuleList<'a>,
    state: ListState,
    table_state: TableState,
    mode: PasswordMode,
}

enum PasswordMode<'a> {
    PasswordEntered(Cow<'a,str>),
    PasswordEntering,
    NoPassword,
}

impl<'a> ModuleUI<'a> {
    pub fn new(module_list: ModuleList<'a>) -> Self {
        Self {
            module_list,
            state: ListState::default(),
            table_state: TableState::default(),
            mode: PasswordMode::NoPassword,
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

fn draw_module_list<B: Backend>(f: &mut Frame<B>, app: &mut ModuleUI) {
    let block = Block::default().title("Modules").borders(Borders::ALL);
    let items: Vec<ListItem> = app
        .module_list
        .modules
        .iter()
        .map(|(name, _, _)| ListItem::new(name.as_ref()))
        .collect();
    let list = List::new(items)
        .block(block)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Green))
        .highlight_symbol(">");
    f.render_stateful_widget(list, f.size(), &mut app.state);
}

fn ui<B: Backend>(f: &mut Frame<B>, app: &mut ModuleUI) {
    draw_module_list(f, app);
}

fn prompt_password(f: &mut Frame<B>) ->  {

}

fn draw_module_selected<B: Backend>(f: &mut Frame<B>, app: &mut ModuleUI) {
    let block = Block::default().title("Passwords").borders(Borders::ALL);
    let entries: Option<Vec<Row>> = app.state.selected().and_then(|i| app.module_list.modules.get(i)).and_then(|x| {
        match x.2 {
            Some(entry) => Some(entry.iter().map(|(k ,v)| Row::new(vec![k.as_ref(), v.as_ref()])).collect())
            None => {
                if let Some(der_file) = x.1 {
                    let entries = 
                }
            }
        }
    })

}

pub fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: ModuleUI) -> std::io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &mut app))?;
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Down => app.next(),
                KeyCode::Up => app.previous(),
                _ => {}
            }
        }
    }
}
