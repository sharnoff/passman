//! The main application logic

use crate::crypt;
use crate::utils::Base64Vec;
use fuzzy_matcher::{skim::SkimMatcherV2, FuzzyMatcher};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fs::{self, File};
use std::io::{self, Write};
use std::mem;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::SystemTime;
use termion::event::{Event, Key};
use tui::style::Color;

/// The primary application, with storage for all of the entries
pub struct App {
    pub entries: Entries,
    pub selected: SelectState,
    pub key: Option<String>,
    // The list of entries available after filtering by the key, given by their indices in
    // `entries.inner`
    pub filter: Option<Vec<usize>>,
    pub start_entries_row: usize,
    pub selected_entries_row: usize,
    pub last_entries_height: AtomicUsize,
    pub unsaved: bool,
    pub file_name: String,
    pub main_selected: EntrySelectState,
    pub search_filter: Option<String>,
    pub displayed_entry_idx: Option<usize>,
}

/// A collection of values for serializing and deserializing persistent app data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entries {
    pub token: Base64Vec,
    pub iv: Base64Vec,
    pub last_update: SystemTime,
    pub inner: Vec<Entry>,
}

/// A single, named entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub tags: Vec<String>,
    pub fields: Vec<Field>,
    pub first_added: SystemTime,
    pub last_update: SystemTime,
}

/// A single field of an [`Entry`](struct.Entry.html)
///
/// The value given may either be `Basic` (unencrypted) or `Protected`; this is given by the
/// `Value` enum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    pub value: Value,
}

/// A single field value, possibly encrypted
///
/// We represent an encrypted value as a `Vec<u8>`, wrapped for the serialization provided by
/// [`Base64Vec`].
///
/// [`Base64Vec`]: ../utils/struct.Base64Vec.html
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Value {
    Basic(String),
    Protected(Base64Vec),
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

/// The types of inputs that may be given inside the
pub enum CommandKind {
    Search {
        return_to_main: bool,
        previous: Option<String>,
    },
    Command {
        return_to_main: bool,
    },
    ModifyEntry {
        name: Option<String>,
    },
    Decrypt {
        return_to_main: bool,
        redo: bool,
    },
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
    /// Instantiates the application, loading the persistent data from the given data
    pub fn new(args: clap::App) -> Option<Result<App, io::Error>> {
        let matches = args.get_matches();
        // We're safe to unwrap here because the "FILE" field is required
        let file = matches.value_of("FILE").unwrap();

        if matches.is_present("new") {
            return match App::create_new(file) {
                Err(Some(e)) => {
                    eprintln!("Failed to initialize into file {:?}: {:?}", file, e);
                    Some(Err(e))
                }
                Err(None) => None,
                Ok(()) => {
                    eprintln!("Successfully initialized into file {:?}", file);
                    None
                }
            };
        }

        let input = match fs::read_to_string(file) {
            Err(e) => return Some(Err(e)),
            Ok(inp) => inp,
        };

        let entries = match serde_yaml::from_str(&input) {
            Ok(es) => es,
            Err(e) => {
                eprintln!("Failed to deserialize yaml file {:?}: {}", file, e);
                return None;
            }
        };

        Some(Ok(App {
            entries,
            selected: SelectState::Entries,
            key: None,
            filter: None,
            start_entries_row: 0,
            selected_entries_row: 0,
            last_entries_height: AtomicUsize::new(0),
            unsaved: false,
            file_name: file.into(),
            main_selected: EntrySelectState::Name,
            search_filter: None,
            displayed_entry_idx: None,
        }))
    }

    fn create_new(file_name: &str) -> Result<(), Option<io::Error>> {
        let mut file = File::create(file_name).unwrap();

        let pwd = rpassword::read_password_from_tty(Some("Please enter an encryption key: "))?;

        let iv = crypt::gen_iv();
        let token = crypt::encrypt_with(&pwd, crate::ENCRYPT_TOKEN.as_ref(), &iv);

        let entries = Entries {
            token: Base64Vec(token),
            iv: Base64Vec(Vec::from(iv.as_ref())),
            last_update: SystemTime::now(),
            inner: Vec::new(),
        };

        let s = serde_yaml::to_string(&entries).unwrap();
        write!(file, "{}", s)?;
        file.flush()?;
        println!(
            "Generation successful! Wrote {} bytes to '{}'",
            s.len(),
            file_name
        );

        Ok(())
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

        fn take(s: &mut String) -> String {
            mem::replace(s, String::new())
        }

        match key {
            Key::Backspace => {
                drop(value.pop());

                if is_search {
                    App::set_filter(
                        &mut self.filter,
                        &mut self.search_filter,
                        Some(value.clone()),
                        &self.entries.inner,
                    );
                }
            }
            Key::Char('\n') => match kind {
                CommandKind::Search { return_to_main, .. } => {
                    App::set_filter(
                        &mut self.filter,
                        &mut self.search_filter,
                        Some(take(value)),
                        &self.entries.inner,
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
                CommandKind::ModifyEntry { name } => {
                    let entry = &mut self.entries.inner[self.displayed_entry_idx.unwrap()];
                    let mut changed = true;
                    match self.main_selected {
                        EntrySelectState::Name => {
                            entry.name = take(value);
                        }
                        EntrySelectState::Tags => {
                            entry.tags = value.split(',').map(String::from).collect();
                        }
                        EntrySelectState::Field { idx } => match name.as_mut() {
                            // If we've already entered the name, then we're done entering the
                            // value for the field
                            Some(n) => {
                                entry.fields[idx] = Field {
                                    name: take(n),
                                    value: Value::Basic(take(value)),
                                };
                            }
                            // Otherwise, we should move on to entering the value
                            None => {
                                *name = Some(take(value));
                                *value = entry.fields[idx]
                                    .value
                                    .format(self.key.as_ref(), self.entries.iv.as_ref());
                                changed = false;
                            }
                        },
                        EntrySelectState::Plus => match name.as_mut() {
                            Some(n) => {
                                entry.fields.push(Field {
                                    name: take(n),
                                    value: Value::Basic(take(value)),
                                });
                            }
                            None => {
                                *name = Some(take(value));
                                changed = false;
                            }
                        },
                    }

                    if changed {
                        let now = SystemTime::now();
                        self.entries.last_update = now;
                        entry.last_update = now;
                        self.selected = SelectState::Main;
                        self.unsaved = true;
                    }
                }
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
                        &mut self.search_filter,
                        Some(value.clone()),
                        &self.entries.inner,
                    );
                }
            }
            Key::Esc => match kind {
                CommandKind::Search {
                    return_to_main,
                    previous,
                } => {
                    App::set_filter(
                        &mut self.filter,
                        &mut self.search_filter,
                        previous.clone(),
                        &self.entries.inner,
                    );
                    match return_to_main {
                        true => self.selected = SelectState::Main,
                        false => self.selected = SelectState::Entries,
                    }
                }
                CommandKind::Command { return_to_main }
                | CommandKind::Decrypt { return_to_main, .. } => {
                    let return_to_main = *return_to_main;
                    let value_cloned = value.clone();
                    drop((kind, value));
                    let should_continue = self.execute_command(&value_cloned, return_to_main);
                    if !should_continue {
                        return false;
                    }
                }
                CommandKind::ModifyEntry { .. } => self.selected = SelectState::Main,
            },
            _ => return true,
        }

        true
    }

    fn handle_main_cmd(&mut self, cmd: Cmd) -> bool {
        let entry = self.displayed_entry_idx.map(|i| &self.entries.inner[i]);

        match cmd {
            Cmd::Left => self.selected = SelectState::Entries,
            Cmd::Right => (),
            Cmd::Down | Cmd::Up | Cmd::Select if entry.is_none() => (),
            Cmd::Down => {
                let new_selected = match self.main_selected {
                    EntrySelectState::Name => EntrySelectState::Tags,
                    EntrySelectState::Tags => match entry.unwrap().fields.len() {
                        0 => EntrySelectState::Plus,
                        _ => EntrySelectState::Field { idx: 0 },
                    },
                    EntrySelectState::Field { idx } => {
                        if idx == entry.unwrap().fields.len() - 1 {
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
                    EntrySelectState::Plus => match entry.unwrap().fields.len() {
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
                        previous: self.search_filter.take(),
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
            Cmd::Quit => return !self.try_quit(),
            Cmd::Select => {
                let entry = &self.entries.inner[self.displayed_entry_idx.unwrap()];

                let value = match self.main_selected {
                    EntrySelectState::Name => (&entry.name).into(),
                    EntrySelectState::Tags => entry.tags.join(","),
                    EntrySelectState::Field { idx } => entry.fields[idx].name.clone(),
                    EntrySelectState::Plus => "".into(),
                };

                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::ModifyEntry { name: None },
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

        let entry = match self.displayed_entry_idx {
            Some(i) => &mut self.entries.inner[i],
            None => return true,
        };

        match key {
            // Delete a single field
            Key::Char('d') => {
                let field_idx = match self.main_selected {
                    EntrySelectState::Field { idx } => idx,
                    _ => return true,
                };

                entry.fields.remove(field_idx);
                self.main_selected = match entry.fields.len() {
                    0 => EntrySelectState::Tags,
                    _ => EntrySelectState::Field {
                        idx: field_idx.saturating_sub(1),
                    },
                };
            }

            // Swap the encryption on a field
            Key::Char('s') => {
                let field = match self.main_selected {
                    EntrySelectState::Field { idx } => &mut entry.fields[idx],
                    _ => return true,
                };

                let key = match self.key.as_ref() {
                    Some(k) => k,
                    // If we haven't decrypted the contents, we can't do anything. We'll produce a
                    // pop-up error
                    None => {
                        self.selected = SelectState::PopUp {
                            header: "Contents not decrypted",
                            message: vec![
                                "Cannot swap encryption on this field; the contents have not yet been decrypted.".into(),
                                "Help: To decrypt the contents of the entries, use ':unlock'"
                                    .into(),
                            ],
                            border_color: Color::Yellow,
                        };
                        return true;
                    }
                };

                match &mut field.value {
                    Value::Basic(s) => {
                        let encrypted =
                            crypt::encrypt_with(&key, s.as_ref(), self.entries.iv.as_ref());
                        field.value = Value::Protected(Base64Vec(encrypted));
                    }
                    Value::Protected(bytes) => {
                        let res =
                            crypt::decrypt_with(&key, bytes.as_ref(), self.entries.iv.as_ref())
                                .and_then(|bytes| String::from_utf8(bytes).ok());
                        match res {
                            Some(s) => field.value = Value::Basic(s),
                            None => {
                                self.selected = SelectState::PopUp {
                                    header: "Decryption error occured",
                                    message: vec![
                                        "This may be due to an invalid key; to re-enter, use ':unlock!'".into(),
                                    ],
                                    border_color: Color::Red,
                                };
                            }
                        }
                    }
                }
            }

            // Add a field
            Key::Char('+') => {
                // We can delegate the work by simply emulating the processes that already happen
                // for adding a field - even though this is a bit of a hack, it means we don't need
                // to duplicate code.
                self.main_selected = EntrySelectState::Plus;
                self.handle_main_cmd(Cmd::Select);
            }
            _ => (),
        }

        true
    }

    fn handle_entries_cmd(&mut self, cmd: Cmd) -> bool {
        let num_items = match self.filter.as_ref() {
            Some(v) => v.len(),
            None => self.entries.inner.len(),
        };

        match cmd {
            Cmd::Left => (),
            Cmd::Right => self.selected = SelectState::Main,
            Cmd::Down | Cmd::Up | Cmd::ScrollDown | Cmd::ScrollUp if num_items == 0 => (),
            Cmd::Down => {
                if self.start_entries_row + self.selected_entries_row >= num_items - 1 {
                    return true;
                }

                let last_height = self.last_entries_height.load(SeqCst);
                if self.selected_entries_row < last_height - 1 {
                    self.selected_entries_row += 1;
                } else {
                    self.start_entries_row += 1;
                }
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
                        previous: self.search_filter.take(),
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
                let idx = self.selected_entries_row + self.start_entries_row;

                let entry_idx = match self.filter.as_ref() {
                    Some(v) if v.is_empty() => return true,
                    Some(list) => list[idx],
                    None => idx,
                };

                self.displayed_entry_idx = Some(entry_idx);
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
                let now = SystemTime::now();
                self.entries.inner.push(Entry {
                    name: "<New Entry>".into(),
                    tags: Vec::new(),
                    fields: Vec::new(),
                    first_added: now,
                    last_update: now,
                });
                self.entries.last_update = now;

                self.displayed_entry_idx = Some(self.entries.inner.len() - 1);
                self.main_selected = EntrySelectState::Name;
                self.selected = SelectState::BottomCommand {
                    kind: CommandKind::ModifyEntry { name: None },
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
            "w" | "write" | "w(rite)" => drop(self.write(return_to_main)),

            // Write-quit
            "wq" => {
                if let Ok(()) = self.write(return_to_main) {
                    return false;
                }
            }

            "delete" => match self.displayed_entry_idx {
                Some(idx) if return_to_main => {
                    self.entries.inner.remove(idx);
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

                    self.unsaved = true;
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
                        border_color: Color::Blue,
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
                        border_color: Color::Blue,
                    };
                }
            },

            // no such command
            _ => {
                self.selected = SelectState::PopUp {
                    header: "Unknown Command",
                    message: vec![format!("No command found with name '{}'", cmd)],
                    border_color: Color::Red,
                }
            }
        }

        true
    }

    fn set_filter(
        filter: &mut Option<Vec<usize>>,
        key: &mut Option<String>,
        new: Option<String>,
        entries: &[Entry],
    ) {
        *key = new;
        let key = match key {
            None => {
                *filter = None;
                return;
            }
            Some(k) if k.is_empty() => {
                *key = None;
                *filter = None;
                return;
            }
            Some(k) => k,
        };

        let matcher = SkimMatcherV2::default();
        let mut matches = entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.fuzzy_match(&matcher, &key).map(|v| (i, v)))
            .collect::<Vec<_>>();

        // Sort in reverse order so that high-value keys are first
        matches.sort_by_key(|(_, v)| -v);
        *filter = Some(matches.into_iter().map(|(i, _v)| i).collect());
    }

    /// Attempt to write the content of `self.entries` to the loaded file, producing a pop-up if
    /// it fails
    fn write(&mut self, return_to_main: bool) -> Result<(), ()> {
        // Try to open the file
        let res = File::create(&self.file_name).and_then(|mut f| {
            let s = serde_yaml::to_string(&self.entries).unwrap();
            write!(f, "{}", s).and_then(|_| f.flush())
        });

        match res {
            Ok(()) => {
                self.unsaved = false;
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
                    border_color: Color::Red,
                };

                Err(())
            }
        }
    }

    /// Attempt to decrypt the content of `self.entries`, producing a pop-up widget upon failure
    fn decrypt(&mut self, key: String, return_to_main: bool, force: bool) {
        if self.key.is_some() && !force {
            self.selected = SelectState::PopUp {
                header: "Already decrypted",
                message: vec![
                    "You've already decrypted the contents!".into(),
                    "To force a different key, try adding an exlamation mark:".into(),
                    "  ':decrypt!' or ':unlock!'".into(),
                ],
                border_color: Color::Blue,
            };
            return;
        }

        let cipher_token = self.entries.token.as_ref();
        let iv = self.entries.iv.as_ref();
        let decrypted_token = crypt::decrypt_with(&key, cipher_token, iv);

        if let Some(t) = decrypted_token {
            if &t == &crate::ENCRYPT_TOKEN.as_bytes() {
                self.key = Some(key);
                match return_to_main {
                    true => self.selected = SelectState::Main,
                    false => self.selected = SelectState::Entries,
                }
                return;
            }
        }

        self.selected = SelectState::PopUp {
            header: "Failed to decrypt",
            message: vec!["Could not decrypt the contents; the entered key was incorrect".into()],
            border_color: Color::Red,
        };
    }

    /// Attempts to quit, returning whether it can successfully done
    fn try_quit(&mut self) -> bool {
        match self.unsaved {
            false => true,
            true => {
                self.selected = SelectState::PopUp {
                    header: "Warning: There are unsaved changes",
                    message: vec![
                        "To save and exit use, use ':wq'.".into(),
                        "Otherwise, to exit without saving, use ':q!'.".into(),
                    ],
                    border_color: Color::Yellow,
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

impl Entry {
    pub fn fuzzy_match(&self, matcher: &SkimMatcherV2, target: &str) -> Option<i64> {
        (self.tags.iter())
            .map(|t| matcher.fuzzy_match(t, target))
            .max()
            .unwrap_or_default()
            .max(matcher.fuzzy_match(&self.name, target))
    }
}

impl Value {
    pub fn format(&self, key: Option<impl AsRef<str>>, iv: &[u8]) -> String {
        match &self {
            Value::Basic(s) => s.clone(),
            Value::Protected(bytes) => match key {
                None => "<Protected>".into(),
                Some(key) => {
                    let res = crypt::decrypt_with(key.as_ref(), bytes.as_ref(), iv)
                        .and_then(|bs| String::from_utf8(bs).ok());
                    match res {
                        None => "<Decryption error>".into(),
                        Some(decrypted) => decrypted,
                    }
                }
            },
        }
    }
}
