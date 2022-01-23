use crate::ui;
use crate::version::{
    self, DecryptError, FieldBuilder, FileContent, GetValueError, PlaintextValue,
    SwapEncryptionError, UnsupportedFeature,
};
use fuzzy_matcher::{skim::SkimMatcherV2, FuzzyMatcher};
use lazy_static::lazy_static;
use signal_hook::{consts::SIGWINCH, iterator::Signals};
use std::convert::TryFrom;
use std::fmt::Display;
use std::fs::File;
use std::io::{self, Write};
use std::mem::take;
use std::path::PathBuf;
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering::Acquire};
use std::sync::{mpsc, Mutex};
use std::thread;
use termion::event::{Event, Key};
use termion::input::TermRead;
use tui::style::Color;

pub fn run(file_path: PathBuf) {
    // Helper function to extract out the value from a `Result`
    fn handle<T, E: Display>(val: Result<T, E>, err_msg: &str) -> T {
        match val {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}: {}", err_msg, e);
                exit(1);
            }
        }
    }

    let mut app = App::new(file_path);
    let mut term = handle(ui::setup_term(), "failed to setup terminal");

    // We start off by drawing the app once, just so that we aren't waiting for a keypress to
    // display anything
    handle(ui::draw(&mut term, &app), "failed to draw to the screen");

    for item in handle(events(), "failed to initialize event loop") {
        if let Some(event) = item {
            let event = match event {
                // If we encountered an error, it's likely because our IO got disconnected or
                // something. We probably won't be able to display anything anyways.
                Err(_) => exit(1),
                Ok(ev) => ev,
            };

            if !app.handle(event) {
                let code = match term.clear() {
                    Ok(_) => 0,
                    Err(_) => 1,
                };

                exit(code);
            }
        }

        handle(ui::draw(&mut term, &app), "failed to draw to the screen");
    }
}

lazy_static! {
    pub static ref SIGNAL_TX: Mutex<Option<mpsc::Sender<Option<io::Result<Event>>>>> =
        Mutex::new(None);
}

/// Creates an iterator over key events and resizes
///
/// Normal events are encoded as `Some(e)`, while resizes are just `None`.
fn events() -> io::Result<impl Iterator<Item = Option<io::Result<Event>>>> {
    // In order to do this properly, we need multiple threads to handle it
    struct Iter {
        rx: mpsc::Receiver<Option<io::Result<Event>>>,
    }

    impl Iterator for Iter {
        type Item = Option<io::Result<Event>>;

        fn next(&mut self) -> Option<Self::Item> {
            self.rx.recv().ok()
        }
    }

    let (tx, rx) = mpsc::channel();
    *SIGNAL_TX.lock().unwrap() = Some(tx.clone());
    let iter = Iter { rx };

    // We'll spawn three threads to handle sending into the channel. The first will produce events
    // from resizes:
    let mut signals = Signals::new(&[SIGWINCH])?;
    let tx_cloned = tx.clone();
    thread::spawn(move || {
        for _ in &mut signals {
            tx_cloned.send(None).unwrap();
        }
    });

    // While the second will simply forward on the events from stdin, wrapping them with `Some`
    thread::spawn(move || {
        for res in io::stdin().events() {
            tx.send(Some(res)).unwrap();
        }
    });

    Ok(iter)
}

/// All of the containing information about the currently-running application
pub struct App {
    pub entries: Box<dyn FileContent>,

    // Where on the screen is the cursor?
    pub selected: SelectState,

    // The list of entries after filtering by the search term, given by their indices in the inner
    // array from `entries`. This value is `None` if there's no search term.
    pub filter: Option<Vec<usize>>,
    pub search_term: Option<String>,

    // The index in `entries` or `filter` that's displayed at the top of the entries bar
    pub start_entries_row: usize,
    // The index *in what's available on-screen* of the selected entry
    pub selected_entries_row: usize,
    // The number of entries that were visible when last displayed
    pub last_entries_height: AtomicUsize,

    pub file_path: PathBuf,
    // If we have an entry open, where is the cursor?
    pub main_selected: EntrySelectState,
    // If there's an entry currently being displayed, this gives the index of that entry
    pub displayed_entry_idx: Option<usize>,
}

/// The region that is currently selected (or should be viewed)
pub enum SelectState {
    /// The center body has been selected
    Main,
    /// The left-hand entries bar has been selected
    Entries,
    /// Some textual user input is being added to inside the bottom bar
    BottomCommand {
        kind: CommandKind,
        value: String,
        as_stars: bool,
    },

    /// A center pop-up to display a prominent message to the user
    PopUp {
        header: &'static str,
        message: Vec<String>,
        border_color: Color,
    },
}

/// The part of the currently-displayed entry that has the cursor over it
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EntrySelectState {
    Name,
    Tags,
    Field { idx: usize },
    Plus,
}

pub enum CommandKind {
    Search {
        return_to_main: bool,
        previous: Option<String>,
    },
    Command {
        return_to_main: bool,
    },
    ModifyEntryMeta,
    ModifyField {
        // The bulider is represented as an Option so that we can take the value once we're done.
        // This value will never *actually* equal `None`.
        builder: Option<Box<dyn FieldBuilder>>,
        state: ModifyFieldState,
        value_kind: NewValueKind,
        old_value: Option<PlaintextValue>,
        field_idx: usize,
    },
    Decrypt {
        return_to_main: bool,
        redo: bool,
    },
}

pub enum NewValueKind {
    Manual,
    Totp,
}

pub enum ModifyFieldState {
    Name,
    ManualValue { protected: bool },
    TotpIssuer,
    // While getting the secret, we need to store the previously-entered 'issuer'
    TotpSecret { issuer: String },
}

#[derive(Debug, Copy, Clone)]
enum Cmd {
    Up,
    Down,
    Left,
    Right,
    ScrollUp,
    ScrollDown,
    StartSearch,
    StartCommand,
    Quit,
    Select,
}

impl App {
    /// Initializes the `App` from the given arguments, exiting on error
    fn new(file_path: PathBuf) -> Self {
        let (entries, maybe_warning) = version::parse(&file_path);

        let selected = match maybe_warning {
            None => SelectState::Entries,
            Some(w) => SelectState::PopUp {
                header: "Warning: old file format",
                message: vec![
                    w.reason.to_owned(),
                    "To update, use the 'update' subcommand (passman update ...).".to_owned(),
                ],
                border_color: ui::WARNING_COLOR,
            },
        };

        App {
            entries,
            selected,
            filter: None,
            search_term: None,
            start_entries_row: 0,
            selected_entries_row: 0,
            last_entries_height: AtomicUsize::new(0),
            file_path,
            main_selected: EntrySelectState::Name,
            displayed_entry_idx: None,
        }
    }

    /// Handles a single key input, changing the app state
    pub fn handle(&mut self, event: Event) -> bool {
        if let SelectState::PopUp { .. } = self.selected {
            match event {
                Event::Key(key) => {
                    self.selected = SelectState::Main;
                    if let Key::Char('\n') = key {
                        return true;
                    }
                }
                _ => return true,
            }
        }

        // Because handling key inputs for the bottom bar would either require (1) re-asserting that
        // `self.selected` has the `BottomCommand` variant or (2) creating aliased mutable
        // references as we pass the value to a handler, we just do the handling for the bottom bar
        // inside this function and dispatch for the other two selection states.
        let (kind, value) = match &mut self.selected {
            SelectState::Main => {
                return match Cmd::try_from(event.clone()) {
                    Ok(cmd) => self.handle_main_cmd(cmd),
                    Err(()) => self.handle_main_event(event),
                }
            }
            SelectState::Entries => {
                return match Cmd::try_from(event.clone()) {
                    Ok(cmd) => self.handle_entries_cmd(cmd),
                    Err(()) => self.handle_entries_event(event),
                }
            }
            SelectState::BottomCommand {
                kind: ref mut k,
                value: ref mut v,
                ..
            } => (k, v),
            SelectState::PopUp { .. } => unreachable!(),
        };

        // Now we'll handle input for bottom-bar values
        let key = match event {
            Event::Key(k) => k,
            _ => return true,
        };

        let is_search = match kind {
            CommandKind::Search { .. } => true,
            _ => false,
        };

        match key {
            Key::Backspace => {
                value.pop();

                if is_search {
                    App::set_filter(
                        &mut self.filter,
                        &mut self.search_term,
                        Some(value.clone()),
                        &*self.entries,
                    );
                    self.update_displayed_entry();
                }
            }
            Key::Char('\n') => match kind {
                CommandKind::Search { return_to_main, .. } => {
                    App::set_filter(
                        &mut self.filter,
                        &mut self.search_term,
                        Some(take(value)),
                        &*self.entries,
                    );
                    self.start_entries_row = 0;
                    self.selected_entries_row = 0;
                    match return_to_main {
                        true => self.selected = SelectState::Main,
                        false => self.selected = SelectState::Entries,
                    }
                }
                CommandKind::Command { return_to_main } => {
                    let return_to_main = *return_to_main;
                    let value_cloned = value.clone();
                    drop((kind, value));
                    let should_continue = self.execute_command(&value_cloned, return_to_main);
                    if !should_continue {
                        return false;
                    }
                }
                CommandKind::ModifyEntryMeta => {
                    let mut entry = self.entries.entry_mut(self.displayed_entry_idx.unwrap());
                    match self.main_selected {
                        EntrySelectState::Name => entry.set_name(take(value)),
                        EntrySelectState::Tags => {
                            let new_tags = value.split(',').map(String::from).collect();
                            entry.set_tags(new_tags);
                        }
                        // These are handled by `CommandKind::ModifyField` instead:
                        EntrySelectState::Field { .. } | EntrySelectState::Plus => unreachable!(),
                    }

                    self.selected = SelectState::Main;
                }
                CommandKind::ModifyField {
                    builder,
                    state,
                    old_value,
                    value_kind,
                    field_idx,
                } => match state {
                    ModifyFieldState::Name => {
                        builder.as_mut().unwrap().set_name(take(value));
                        match value_kind {
                            NewValueKind::Manual => {
                                let mut protected = false;
                                *value = match old_value {
                                    // Don't make a protected value unprotected
                                    Some(PlaintextValue::Manual {
                                        value: v,
                                        protected: p,
                                    }) => {
                                        protected = *p;
                                        v.clone()
                                    }
                                    _ => "".to_owned(),
                                };
                                *state = ModifyFieldState::ManualValue { protected };
                            }
                            NewValueKind::Totp => {
                                // Ask for the issuer first:
                                *state = ModifyFieldState::TotpIssuer;
                                *value = match old_value {
                                    Some(PlaintextValue::Totp { issuer, .. }) => issuer.clone(),
                                    _ => "".to_owned(),
                                };
                            }
                        }
                    }
                    ModifyFieldState::ManualValue { protected } => {
                        let mut builder = take(builder).unwrap();

                        builder.set_value(PlaintextValue::Manual {
                            value: take(value),
                            protected: *protected,
                        });

                        let mut entry = self.entries.entry_mut(self.displayed_entry_idx.unwrap());
                        match entry.set_field(*field_idx, builder) {
                            // If setting the field went ok, we can just return to the entry
                            Ok(()) => self.selected = SelectState::Main,
                            Err(e) => {
                                self.selected = SelectState::PopUp {
                                    header: "Error: Couldn't set field",
                                    message: vec![e.to_string()],
                                    border_color: ui::ERROR_COLOR,
                                }
                            }
                        }
                    }
                    ModifyFieldState::TotpIssuer => {
                        *state = ModifyFieldState::TotpSecret {
                            issuer: take(value),
                        };
                        // Set the secret based on the previous value:
                        *value = match old_value {
                            Some(PlaintextValue::Totp { secret, .. }) => secret.clone(),
                            _ => "".to_owned(),
                        };
                    }
                    ModifyFieldState::TotpSecret { issuer } => {
                        let mut builder = take(builder).unwrap();
                        builder.set_value(PlaintextValue::Totp {
                            issuer: take(issuer),
                            secret: take(value),
                        });

                        let mut entry = self.entries.entry_mut(self.displayed_entry_idx.unwrap());
                        match entry.set_field(*field_idx, builder) {
                            // If setting the field went ok, we can just return to the entry
                            Ok(()) => self.selected = SelectState::Main,
                            Err(e) => {
                                self.selected = SelectState::PopUp {
                                    header: "Error: Couldn't set field",
                                    message: vec![e.to_string()],
                                    border_color: ui::ERROR_COLOR,
                                }
                            }
                        }
                    }
                },
                CommandKind::Decrypt {
                    return_to_main,
                    redo,
                } => {
                    let (return_to_main, redo) = (*return_to_main, *redo);
                    let key = value.clone();
                    drop((kind, value));
                    self.decrypt(key, return_to_main, redo);
                }
            },
            Key::Char(c) => {
                value.push(c);

                if is_search {
                    App::set_filter(
                        &mut self.filter,
                        &mut self.search_term,
                        Some(value.clone()),
                        &*self.entries,
                    );
                    self.update_displayed_entry();
                }
            }
            Key::Esc => match kind {
                CommandKind::Search {
                    return_to_main,
                    previous,
                } => {
                    App::set_filter(
                        &mut self.filter,
                        &mut self.search_term,
                        previous.clone(),
                        &*self.entries,
                    );
                    let return_to_main = *return_to_main;
                    self.displayed_entry_idx = self.sidebar_selected_entry();

                    match return_to_main {
                        true => self.selected = SelectState::Main,
                        false => self.selected = SelectState::Entries,
                    }
                }
                CommandKind::Command { return_to_main }
                | CommandKind::Decrypt { return_to_main, .. } => match *return_to_main {
                    true => self.selected = SelectState::Main,
                    false => self.selected = SelectState::Entries,
                },
                CommandKind::ModifyEntryMeta { .. } | CommandKind::ModifyField { .. } => {
                    self.selected = SelectState::Main
                }
            },
            _ => return true,
        }

        true
    }

    fn handle_main_cmd(&mut self, cmd: Cmd) -> bool {
        let entry = self.displayed_entry_idx.map(|i| self.entries.entry(i));

        match cmd {
            Cmd::Left => {
                if let Some(i) = self.sidebar_selected_entry() {
                    self.displayed_entry_idx = Some(i);
                }

                self.selected = SelectState::Entries;
            }
            Cmd::Right => (),
            Cmd::Down | Cmd::Up | Cmd::Select if entry.is_none() => (),
            Cmd::Down => {
                let new_selected = match self.main_selected {
                    EntrySelectState::Name => EntrySelectState::Tags,
                    EntrySelectState::Tags => match entry.unwrap().num_fields() {
                        0 => EntrySelectState::Plus,
                        _ => EntrySelectState::Field { idx: 0 },
                    },
                    EntrySelectState::Field { idx } => {
                        if idx == entry.unwrap().num_fields() - 1 {
                            EntrySelectState::Plus
                        } else {
                            EntrySelectState::Field { idx: idx + 1 }
                        }
                    }
                    EntrySelectState::Plus => EntrySelectState::Plus,
                };

                self.main_selected = new_selected;
            }
            Cmd::Up => {
                let new_selected = match self.main_selected {
                    EntrySelectState::Name => EntrySelectState::Name,
                    EntrySelectState::Tags => EntrySelectState::Name,
                    EntrySelectState::Field { idx: 0 } => EntrySelectState::Tags,
                    EntrySelectState::Field { idx } => EntrySelectState::Field { idx: idx - 1 },
                    EntrySelectState::Plus => match entry.unwrap().num_fields() {
                        0 => EntrySelectState::Tags,
                        n => EntrySelectState::Field { idx: n - 1 },
                    },
                };

                self.main_selected = new_selected;
            }
            // Currently there's no scrolling for viewing entries
            Cmd::ScrollDown | Cmd::ScrollUp => (),
            Cmd::StartSearch => {
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::Search {
                        return_to_main: true,
                        previous: self.search_term.take(),
                    },
                    value: String::new(),
                    as_stars: false,
                };
            }
            Cmd::StartCommand => {
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::Command {
                        return_to_main: true,
                    },
                    value: String::new(),
                    as_stars: false,
                };
            }
            Cmd::Quit => {
                drop(entry); // Need to explicitly drop this because `Box` has drop glue
                return !self.try_quit();
            }
            Cmd::Select => {
                drop(entry); // Remove the existing entry ref, so we can re-borrow as mutable
                let entry = self.entries.entry_mut(self.displayed_entry_idx.unwrap());

                let kind: CommandKind;

                let value = match self.main_selected {
                    EntrySelectState::Field { idx } => {
                        let mut builder = entry.field_builder();

                        let (value_kind, old_value) = match entry.field(idx).plaintext_value() {
                            Ok(v @ PlaintextValue::Manual { .. }) => {
                                builder.make_manual();
                                (NewValueKind::Manual, Some(v))
                            }
                            Ok(v @ PlaintextValue::Totp { .. }) => {
                                builder.make_totp().expect("file already has TOTP fields");
                                (NewValueKind::Totp, Some(v))
                            }
                            Err(e) => {
                                let mut message = vec![e.to_string()];

                                if let GetValueError::ContentsNotUnlocked = e {
                                    message.push(ui::DECRYPT_HELP_MSG.to_owned());
                                }

                                self.selected = SelectState::PopUp {
                                    header: "Error: Cannot edit field",
                                    message: vec![e.to_string()],
                                    border_color: ui::ERROR_COLOR,
                                };
                                return true;
                            }
                        };

                        kind = CommandKind::ModifyField {
                            builder: Some(builder),
                            state: ModifyFieldState::Name,
                            value_kind,
                            old_value,
                            field_idx: idx,
                        };
                        entry.field(idx).name().to_owned()
                    }
                    EntrySelectState::Plus => {
                        // Using the "+" button always creates a manual field
                        let mut builder = entry.field_builder();
                        builder.make_manual();
                        kind = CommandKind::ModifyField {
                            builder: Some(builder),
                            state: ModifyFieldState::Name,
                            value_kind: NewValueKind::Manual,
                            old_value: None,
                            // "replacing" at index = len is allowed; it adds a field
                            field_idx: entry.num_fields(),
                        };
                        String::new()
                    }
                    EntrySelectState::Name => {
                        kind = CommandKind::ModifyEntryMeta;
                        entry.name().into()
                    }
                    EntrySelectState::Tags => {
                        kind = CommandKind::ModifyEntryMeta;
                        entry.tags().join(",")
                    }
                };

                self.selected = SelectState::BottomCommand {
                    kind,
                    value,
                    as_stars: false,
                };
            }
        }

        true
    }

    /// Handles a single event while the "main view" (the one displaying a single entry) has been
    /// selected
    fn handle_main_event(&mut self, event: Event) -> bool {
        let key = match event {
            Event::Key(k) => k,
            _ => return true,
        };

        let entries_decrypted = self.entries.decrypted();

        let mut entry = match self.displayed_entry_idx {
            Some(i) => self.entries.entry_mut(i),
            None => return true,
        };

        match key {
            // Delete a single field
            Key::Char('d') => {
                let field_idx = match self.main_selected {
                    EntrySelectState::Field { idx } => idx,
                    _ => return true,
                };

                entry.remove_field(field_idx);
                self.main_selected = match entry.num_fields() {
                    0 => EntrySelectState::Tags,
                    _ => EntrySelectState::Field {
                        idx: field_idx.saturating_sub(1),
                    },
                };
            }

            // Swap the encryption on a field
            Key::Char('s') => {
                let field_idx = match self.main_selected {
                    EntrySelectState::Field { idx } => idx,
                    _ => return true,
                };

                // If we haven't decrypted yet, produce a pop-up error
                if !entries_decrypted {
                    self.selected = SelectState::PopUp {
                        header: "Contents not decrypted",
                        message: vec![
                            "Cannot swap encryption on this field; the contents have not yet been decrypted.".into(),
                            ui::DECRYPT_HELP_MSG.to_owned(),
                        ],
                        border_color: ui::WARNING_COLOR,
                    };

                    return true;
                }

                if let Err(e) = entry.field_mut(field_idx).swap_encryption() {
                    let mut message = vec![e.to_string()];
                    if let SwapEncryptionError::ContentsNotUnlocked = e {
                        message.push(ui::DECRYPT_HELP_MSG.to_string());
                    }

                    self.selected = SelectState::PopUp {
                        header: "Error: Can't swap field encryption",
                        message,
                        border_color: ui::ERROR_COLOR,
                    };
                }
            }

            // Add a (manual) field
            Key::Char('+') => {
                // We can delegate the work by simply emulating the processes that already happen
                // for adding a field - even though this is a bit of a hack, it means we don't need
                // to duplicate code.
                self.main_selected = EntrySelectState::Plus;
                drop(entry); // Need to explicitly drop this because `Box` has drop glue
                self.handle_main_cmd(Cmd::Select);
            }

            // Add a TOTP field
            Key::Char('t') => {
                let mut builder = entry.field_builder();
                match builder.make_totp() {
                    Err(e @ UnsupportedFeature::Totp) => {
                        // Add an error pop-up because we couldn't make the builder
                        self.selected = SelectState::PopUp {
                            header: "Error: Cannot make new TOTP field",
                            message: vec![e.to_string()],
                            border_color: ui::ERROR_COLOR,
                        };
                    }
                    Ok(()) => {
                        self.selected = SelectState::BottomCommand {
                            kind: CommandKind::ModifyField {
                                builder: Some(builder),
                                state: ModifyFieldState::Name,
                                value_kind: NewValueKind::Totp,
                                old_value: None,
                                // Setting the field at index = len creates a new one
                                field_idx: entry.num_fields(),
                            },
                            value: "".to_owned(),
                            as_stars: false,
                        };
                    }
                }
            }
            _ => (),
        }

        true
    }

    fn handle_entries_cmd(&mut self, cmd: Cmd) -> bool {
        let num_items = match self.filter.as_ref() {
            Some(v) => v.len(),
            None => self.entries.num_entries(),
        };

        match cmd {
            Cmd::Left => (),
            Cmd::Right => {
                self.selected = SelectState::Main;
            }
            Cmd::Down | Cmd::Up | Cmd::ScrollDown | Cmd::ScrollUp if num_items == 0 => (),
            Cmd::Down => {
                if self.start_entries_row + self.selected_entries_row >= num_items - 1 {
                    return true;
                }

                let last_height = self.last_entries_height.load(Acquire);
                if self.selected_entries_row < last_height - 1 {
                    self.selected_entries_row += 1;
                } else {
                    self.start_entries_row += 1;
                }
                self.displayed_entry_idx = self.sidebar_selected_entry();
            }
            Cmd::Up => {
                if self.start_entries_row == 0 && self.selected_entries_row == 0 {
                    return true;
                }

                if self.selected_entries_row == 0 {
                    self.start_entries_row -= 1;
                } else {
                    self.selected_entries_row -= 1;
                }
                self.displayed_entry_idx = self.sidebar_selected_entry();
            }
            Cmd::ScrollUp => {
                if self.start_entries_row == 0 {
                    return true;
                }

                self.start_entries_row -= 1;
                self.selected_entries_row += 1;
            }
            Cmd::ScrollDown => {
                if self.start_entries_row >= num_items - 1 {
                    return true;
                }

                self.start_entries_row += 1;
                self.selected_entries_row = self.selected_entries_row.saturating_sub(1);
            }
            Cmd::StartSearch => {
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::Search {
                        return_to_main: false,
                        previous: self.search_term.take(),
                    },
                    value: String::new(),
                    as_stars: false,
                };
            }
            Cmd::StartCommand => {
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::Command {
                        return_to_main: false,
                    },
                    value: String::new(),
                    as_stars: false,
                };
            }
            Cmd::Quit => return !self.try_quit(),
            Cmd::Select => {
                let idx = match self.sidebar_selected_entry() {
                    None => return true,
                    Some(i) => i,
                };

                self.displayed_entry_idx = Some(idx);
                self.selected = SelectState::Main;
                self.main_selected = EntrySelectState::Name;
            }
        }

        true
    }

    /// Handles a single event while the entries list has been selected
    fn handle_entries_event(&mut self, _event: Event) -> bool {
        true
    }

    fn execute_command(&mut self, cmd: &str, return_to_main: bool) -> bool {
        match cmd {
            // new entry
            "new" => {
                let new_entry_idx = self.entries.add_empty_entry("<New Entry>".into());
                self.displayed_entry_idx = Some(new_entry_idx);
                self.main_selected = EntrySelectState::Name;
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::ModifyEntryMeta,
                    value: String::new(),
                    as_stars: false,
                };

                return true;
            }

            // unlock / decrypt the contents
            "unlock" | "decrypt" => {
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::Decrypt {
                        return_to_main,
                        redo: false,
                    },
                    value: String::new(),
                    as_stars: true,
                };

                return true;
            }
            "unlock!" | "decrypt!" => {
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::Decrypt {
                        return_to_main,
                        redo: true,
                    },
                    value: String::new(),
                    as_stars: true,
                };
            }

            // Exit
            "q" | "quit" | "q(uit)" => return !self.try_quit(),

            // Force exit
            "q!" | "quit!" | "q(uit)!" => return false,

            // Write
            "w" | "write" | "w(rite)" => {
                // We're fine dropping the `Result` here because it's mostly given as an external
                // indicator of whether the writing was successful - all of the failure logic is
                // handled in `write`
                let _ = self.write(return_to_main);
            }

            // Write-quit
            "wq" => {
                if let Ok(()) = self.write(return_to_main) {
                    return false;
                }
            }

            "delete" => match self.displayed_entry_idx {
                Some(idx) if return_to_main => {
                    self.entries.remove_entry(idx);
                    let removed = match self.filter.as_mut() {
                        Some(filter) => match filter.iter().position(|&i| i == idx) {
                            Some(i) => {
                                filter.remove(i);
                                true
                            }
                            _ => false,
                        },
                        _ => true,
                    };
                    self.displayed_entry_idx = None;

                    // If the entries bar had the entry in view, we should shift what's currently
                    // displayed so that we won't ever end up with nothing in view
                    if removed {
                        self.start_entries_row = self.start_entries_row.saturating_sub(1);
                    }

                    self.selected = SelectState::Entries;
                }

                // If there wasn't a selected entry, we'll say that deletion must be done from
                // within a selected entry
                None => {
                    self.selected = SelectState::PopUp {
                        header: "Cannot delete without entry selection",
                        message: vec![
                            "Help: Select an entry with 'Enter' before using ':delete'".into()
                        ],
                        border_color: ui::INFO_COLOR,
                    };
                }
                Some(_) => {
                    self.selected = SelectState::PopUp {
                        header: "Cannot delete from entries list",
                        message: vec![
                            "Because the entry you'd like to delete is ambiguous, please".into(),
                            "ensure that you have selected (with 'Enter') the entry to delete."
                                .into(),
                        ],
                        border_color: ui::INFO_COLOR,
                    };
                }
            },

            // no such command
            _ => {
                self.selected = SelectState::PopUp {
                    header: "Unknown Command",
                    message: vec![format!("No command found with name '{}'", cmd)],
                    border_color: ui::ERROR_COLOR,
                }
            }
        }

        true
    }

    // Returns the entry index of the currently selected entry in the sidebar on the left --
    // independent of what may displayed inside of the
    fn sidebar_selected_entry(&self) -> Option<usize> {
        let idx = self.selected_entries_row + self.start_entries_row;

        match self.filter.as_ref() {
            Some(list) => list.get(idx).cloned(),
            None if idx >= self.entries.num_entries() => None,
            None => Some(idx),
        }
    }

    /// Updates the index of the currently displayed entry in accordance with the values available
    /// within the sidebar
    fn update_displayed_entry(&mut self) {
        // The maximum index, plus one -- i.e. an exclusive upper bound
        let max_idx = self
            .filter
            .as_ref()
            .map(|filter| filter.len())
            .unwrap_or_else(|| self.entries.num_entries());
        let current_idx = self.start_entries_row + self.selected_entries_row;

        // If the maximum index is zero, we can't have a selected entry to display
        let max_idx = match max_idx.checked_sub(1) {
            Some(i) => i,
            None => {
                self.start_entries_row = 0;
                self.selected_entries_row = 0;
                self.displayed_entry_idx = None;
                return;
            }
        };

        if current_idx > max_idx {
            let diff = current_idx - max_idx;
            let new_start = self.start_entries_row.saturating_sub(diff);
            let remaining_diff = diff - (self.start_entries_row - new_start);

            self.start_entries_row = new_start;
            self.selected_entries_row = self.selected_entries_row - remaining_diff;
        }

        self.displayed_entry_idx = self.sidebar_selected_entry();
    }

    fn set_filter(
        filter: &mut Option<Vec<usize>>,
        search_term: &mut Option<String>,
        new_term: Option<String>,
        entries: &dyn FileContent,
    ) {
        *search_term = new_term;
        let term = match search_term {
            None => {
                *filter = None;
                return;
            }
            Some(t) if t.is_empty() => {
                *search_term = None;
                *filter = None;
                return;
            }
            Some(t) => t,
        };

        let matcher = SkimMatcherV2::default();
        let mut matches = entries
            .all_entries()
            .into_iter()
            .enumerate()
            .filter_map(|(i, e)| {
                let score = fuzzy_match(term, &matcher, e.name(), e.tags())?;
                Some((i, score))
            })
            .collect::<Vec<_>>();

        // Sort in reverse order so that high-value keys are first
        matches.sort_by_key(|(_, v)| -v);
        *filter = Some(matches.into_iter().map(|(i, _v)| i).collect());
    }

    /// Attempt to write the content of `self.entries` to the loaded file, producing a pop-up if
    /// it fails
    fn write(&mut self, return_to_main: bool) -> Result<(), ()> {
        // Try to open the file
        let res = File::create(&self.file_path).and_then(|mut f| {
            let s = self.entries.write();
            write!(f, "{}", s).and_then(|_| f.flush())
        });

        match res {
            Ok(()) => {
                self.entries.mark_saved();
                self.selected = match return_to_main {
                    true => SelectState::Main,
                    false => SelectState::Entries,
                };
                Ok(())
            }
            Err(e) => {
                // If we failed, we'll produce a pop-up and return that there was an error
                self.selected = SelectState::PopUp {
                    header: "Error: Failed to write to file",
                    message: vec![format!("Error: {}", e)],
                    border_color: ui::ERROR_COLOR,
                };

                Err(())
            }
        }
    }

    /// Attempt to decrypt the content of `self.entries`, producing a pop-up widget upon failure
    fn decrypt(&mut self, key: String, return_to_main: bool, force: bool) {
        if self.entries.decrypted() && !force {
            self.selected = SelectState::PopUp {
                header: "Already decrypted",
                message: vec![
                    "You've already decrypted the contents!".into(),
                    "To force a different key, try adding an exlamation mark:".into(),
                    "  ':decrypt!' or ':unlock!'".into(),
                ],
                border_color: ui::INFO_COLOR,
            };
            return;
        }

        match self.entries.set_key(key) {
            Ok(()) => match return_to_main {
                true => self.selected = SelectState::Main,
                false => self.selected = SelectState::Entries,
            },
            Err(DecryptError::BadCrypt | DecryptError::BadUtf8) => {
                self.selected = SelectState::PopUp {
                    header: "Error: Failed to decrypt",
                    message: vec![
                        "Could not decrypt the contents; the entered key was incorrect".into(),
                    ],
                    border_color: ui::ERROR_COLOR,
                };
            }
        }
    }

    /// Attempts to quit, returning whether it can successfully done
    fn try_quit(&mut self) -> bool {
        match self.entries.unsaved() {
            false => true,
            true => {
                self.selected = SelectState::PopUp {
                    header: "Warning: There are unsaved changes",
                    message: vec![
                        "To save and exit use, use ':wq'.".into(),
                        "Otherwise, to exit without saving, use ':q!'.".into(),
                    ],
                    border_color: ui::WARNING_COLOR,
                };

                false
            }
        }
    }
}

impl TryFrom<Event> for Cmd {
    type Error = ();

    fn try_from(event: Event) -> Result<Cmd, ()> {
        let key = match event {
            Event::Key(k) => k,
            _ => return Err(()),
        };

        match key {
            Key::Char('h') | Key::Left => Ok(Cmd::Left),
            Key::Char('j') | Key::Down => Ok(Cmd::Down),
            Key::Char('k') | Key::Up => Ok(Cmd::Up),
            Key::Char('l') | Key::Right => Ok(Cmd::Right),
            Key::Ctrl('e') => Ok(Cmd::ScrollDown),
            Key::Ctrl('y') => Ok(Cmd::ScrollUp),
            Key::Char('/') => Ok(Cmd::StartSearch),
            Key::Char(':') => Ok(Cmd::StartCommand),
            Key::Char('q') => Ok(Cmd::Quit),
            Key::Char('\n') => Ok(Cmd::Select),
            _ => Err(()),
        }
    }
}

fn fuzzy_match(target: &str, matcher: &SkimMatcherV2, name: &str, tags: Vec<&str>) -> Option<i64> {
    tags.into_iter()
        .map(|t| matcher.fuzzy_match(t, target))
        .max()
        .unwrap_or_default()
        .max(matcher.fuzzy_match(name, target))
}
