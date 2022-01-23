//! Displays the current state of the `App`

use crate::app::{App, CommandKind, EntrySelectState, ModifyFieldState, NewValueKind, SelectState};
use crate::utils;
use crate::version::{GetValueError, ValueKind};
use std::io::{self, Stdout};
use std::sync::atomic::Ordering::Release;
use termion::raw::{IntoRawMode, RawTerminal};
use tui::backend::TermionBackend;
use tui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans};
use tui::widgets::{self, Block, Borders, Paragraph};

type Backend = TermionBackend<RawTerminal<Stdout>>;
type Terminal = tui::Terminal<Backend>;
type Frame<'a> = tui::terminal::Frame<'a, Backend>;

pub const WARNING_COLOR: Color = Color::Yellow;
pub const ERROR_COLOR: Color = Color::Red;
pub const INFO_COLOR: Color = Color::Blue;

pub static PROTECTED_STR: &str = "<Protected>";
pub static DECRYPT_HELP_MSG: &str = "Help: To decrypt the contents of the entries, use ':unlock'";

const SELECT_STYLE: Style = Style {
    fg: Some(Color::Blue),
    ..default_style()
};

const fn default_style() -> Style {
    Style {
        fg: None,
        bg: None,
        add_modifier: Modifier::empty(),
        sub_modifier: Modifier::empty(),
    }
}

/// Performs the necessary setup for drawing to the screen
///
/// This should only be run once and before ever calling [`draw`].
pub fn setup_term() -> io::Result<Terminal> {
    let stdout = io::stdout().into_raw_mode()?;
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    Ok(terminal)
}

pub fn draw(term: &mut Terminal, app: &App) -> io::Result<()> {
    term.draw(|mut f| {
        // The general layout of the UI can be represented by this diagram:
        //   +-----+---------------------------------+-----+
        //   |     |                                 |saved|
        //   |     |                                 +-----+
        //   |  E  |                                 |  O  |
        //   |  n  |           Main View             |  p  |
        //   |  t  |         *single entry           |  t  |
        //   |  r  |                                 |  i  |
        //   |  i  |                                 |  o  |
        //   |  e  |                                 |  n  |
        //   |  s  |                                 |  s  |
        //   |     +---------------------------------+-----+
        //   |     | Command input                         |
        //   +-----+---------------------------------------+
        // * Note: not to scale
        //
        // Because various components of this are nested, the outer layout only differentiates between
        // the "entries" column and everything else:
        let outer_chunks = horizontal_chunks(
            f.size(),
            vec![Constraint::Min(26), Constraint::Percentage(80)],
        );

        // Next, we differentiate between "main+options" and "command input"
        let cmd_chunks = vertical_chunks(
            outer_chunks[1],
            vec![Constraint::Min(0), Constraint::Length(3)],
        );

        // And for the final two, we again switch between horizontal and vertical layouts
        let main_chunks = horizontal_chunks(
            cmd_chunks[0],
            vec![Constraint::Min(30), Constraint::Length(26)],
        );

        let options_chunks = vertical_chunks(
            main_chunks[1],
            vec![Constraint::Length(4), Constraint::Min(0)],
        );

        render_entries(&mut f, outer_chunks[0], app);
        render_cmd(&mut f, cmd_chunks[1], app);
        render_main(&mut f, main_chunks[0], app);
        render_status(&mut f, options_chunks[0], app);
        render_options(&mut f, options_chunks[1], app);

        // In addition to the above, we'll also render a pop-up if it's there
        if let SelectState::PopUp {
            header,
            message,
            border_color,
        } = &app.selected
        {
            let rect = f.size();
            render_popup(&mut f, rect, header, message, *border_color);
        }
    })?;

    Ok(())
}

fn vertical_chunks(rect: Rect, constraints: Vec<Constraint>) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(rect)
}

fn horizontal_chunks(rect: Rect, constraints: Vec<Constraint>) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(constraints)
        .split(rect)
}

fn render_entries(f: &mut Frame, rect: Rect, app: &App) {
    let title = match app.search_term.as_ref() {
        None => "Entries".into(),
        Some(filter) => format!("Entries // '{}'", filter),
    };

    let (style, start_row, selected_row) = match app.selected {
        SelectState::Entries => (
            SELECT_STYLE,
            app.start_entries_row,
            Some(app.selected_entries_row),
        ),
        _ => (default_style(), 0, None),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(style);

    let num_entries = app.entries.num_entries();
    let entries_list = match app.filter.as_ref() {
        None => app.entries.entries_range(start_row..num_entries),
        Some(list) => list.iter().map(|&i| app.entries.entry(i)).collect(),
    };

    // If there's no available entries, we should display something to indicate that this
    // is the case, and return
    if entries_list.is_empty() {
        let line = match app.filter.is_some() {
            true => "No matches",
            false => "No entries",
        };

        let paragraph = Paragraph::new(vec![Spans::from(Span::raw(line))])
            .block(block)
            .alignment(Alignment::Left);
        f.render_widget(paragraph, rect);
        return;
    }

    let text: Vec<_> = entries_list
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let style = match selected_row == Some(i) {
                true => Style::default().fg(Color::Black).bg(Color::Blue),
                false => Style::default(),
            };

            Spans::from(Span::styled(e.name(), style))
        })
        .collect();

    let paragraph = Paragraph::new(text).block(block).alignment(Alignment::Left);
    f.render_widget(paragraph, rect);

    // We subtract 2 from the height because it has borders on both sides
    if let Some(height) = rect.height.checked_sub(2) {
        app.last_entries_height.store(height as usize, Release);
    }
}

fn render_cmd(f: &mut Frame, rect: Rect, app: &App) {
    let title = match &app.selected {
        SelectState::BottomCommand { kind, .. } => match kind {
            CommandKind::Search { .. } => "Searching entries",
            CommandKind::Command { .. } => "Command input",
            CommandKind::ModifyEntryMeta => match app.main_selected {
                EntrySelectState::Name => "Editing entry name",
                EntrySelectState::Tags => "Editing entry tags",
                EntrySelectState::Field { .. } | EntrySelectState::Plus => unreachable!(),
            },
            CommandKind::ModifyField {
                state, value_kind, ..
            } => match (state, value_kind) {
                (ModifyFieldState::Name, NewValueKind::Manual) => "Editing standard field name",
                (ModifyFieldState::Name, NewValueKind::Totp) => "Editing TOTP field name",
                (ModifyFieldState::ManualValue { protected: false }, _) => {
                    "Editing basic field value"
                }
                (ModifyFieldState::ManualValue { protected: true }, _) => {
                    "Editing protected field value"
                }
                (ModifyFieldState::TotpIssuer, _) => "Editing TOTP field issuer",
                (ModifyFieldState::TotpSecret { .. }, _) => "Editing TOTP field secret",
            },
            CommandKind::Decrypt { .. } => "Decryption key",
        },
        _ => {
            f.render_widget(Block::default().borders(Borders::ALL), rect);
            return;
        }
    };

    let span = match &app.selected {
        SelectState::BottomCommand {
            value, as_stars, ..
        } => match *as_stars {
            false => Span::raw(value),
            true => Span::raw("*".repeat(value.len())),
        },
        _ => unreachable!(),
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(SELECT_STYLE);

    let cursor_style = default_style()
        .bg(Color::White)
        .add_modifier(Modifier::SLOW_BLINK);

    let paragraph = Paragraph::new(Spans(vec![span, Span::styled(" ", cursor_style)]))
        .block(block)
        .alignment(Alignment::Left);

    f.render_widget(paragraph, rect);
}

fn render_main(f: &mut Frame, rect: Rect, app: &App) {
    let (style, selected) = match app.selected {
        SelectState::Main => (SELECT_STYLE, Some(app.main_selected)),
        _ => (default_style(), None),
    };

    let entry = match app.displayed_entry_idx {
        Some(idx) => app.entries.entry(idx),
        None => {
            // If there's no entry selected, we'll just display that there isn't one
            let block = Block::default()
                .title("No entry selected")
                .borders(Borders::ALL)
                .border_style(style);
            f.render_widget(block, rect);
            return;
        }
    };

    const UNDERLINED: Style = Style {
        fg: None,
        bg: None,
        add_modifier: Modifier::UNDERLINED,
        sub_modifier: Modifier::empty(),
    };

    fn styled(
        pre: impl Into<String>,
        fst: impl Into<String>,
        snd: impl Into<String>,
        is_styled: bool,
    ) -> Spans<'static> {
        if !is_styled {
            return Spans::from(Span::raw(format!(
                "{}{}{}",
                pre.into(),
                fst.into(),
                snd.into()
            )));
        }

        Spans(vec![
            Span::raw(pre.into()),
            Span::styled(fst.into(), UNDERLINED),
            Span::styled(snd.into(), UNDERLINED.fg(Color::Black).bg(Color::Blue)),
        ])
    }

    use crate::app::EntrySelectState::{Field, Name, Plus, Tags};

    let mut text = Vec::with_capacity(entry.num_fields() + 5);
    text.push(styled(
        "",
        "Entry name: ",
        format!("\"{}\"", utils::escape_quotes(entry.name())),
        selected == Some(Name),
    ));
    text.push(styled(
        "",
        "Tags: ",
        utils::comma_strings(&entry.tags()),
        selected == Some(Tags),
    ));

    for idx in 0..entry.num_fields() {
        let is_selected = selected == Some(Field { idx });
        let field = entry.field(idx);

        let (prefix, is_protected) = match field.value_kind() {
            ValueKind::Basic => ("  ", false),
            ValueKind::Protected => ("🔒", true),
            ValueKind::Totp => ("⏳", true),
        };

        let value = if is_selected || !is_protected {
            field.value().unwrap_or_else(|e| match e {
                GetValueError::ContentsNotUnlocked => PROTECTED_STR.to_owned(),
                GetValueError::Decrypt(_) => "<BAD CRYPT>".to_owned(),
                GetValueError::BadTotpSecret => "<BAD TOTP SECRET>".to_owned(),
            })
        } else {
            PROTECTED_STR.to_owned()
        };

        text.push(styled(
            prefix,
            format!("{}: ", field.name()),
            value,
            is_selected,
        ));
    }

    text.push(styled("", "", "[+]", selected == Some(Plus)));
    text.push(Spans::from(Span::raw("")));

    let first_added = entry.first_added();
    let last_update = entry.last_update();

    text.push(Spans::from(Span::raw(format!(
        "First added: {}",
        utils::format_time(first_added)
    ))));
    if last_update != first_added {
        text.push(Spans::from(Span::raw(format!(
            "Last updated: {}",
            utils::format_time(last_update)
        ))));
    }

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(format!(
                    "Selected \"{}\"",
                    utils::escape_quotes(entry.name())
                ))
                .borders(Borders::ALL)
                .border_style(style),
        )
        .alignment(Alignment::Left);

    f.render_widget(paragraph, rect);
}

fn render_status(f: &mut Frame, rect: Rect, app: &App) {
    const NO_CHAR: char = '◇';
    const YES_CHAR: char = '◆';

    fn status_char(is_present: bool) -> char {
        match is_present {
            true => YES_CHAR,
            false => NO_CHAR,
        }
    }

    let decrypted = format!("{} Decrypted", status_char(app.entries.decrypted()));
    let unsaved = format!("{} Unsaved", status_char(app.entries.unsaved()));

    let text = vec![
        Spans::from(Span::raw(decrypted)),
        Spans::from(Span::raw(unsaved)),
    ];

    let paragraph = Paragraph::new(text)
        .block(Block::default().title("Status").borders(Borders::ALL))
        .alignment(Alignment::Left);

    f.render_widget(paragraph, rect);
}

fn render_options(f: &mut Frame, rect: Rect, app: &App) {
    use CommandKind::{Command, Decrypt, ModifyEntryMeta, ModifyField, Search};

    #[rustfmt::skip]
    let (normal, moves): (&[_], &[_]) = match app.selected {
        SelectState::Main
        | SelectState::BottomCommand {
            kind: Search { return_to_main: true, ..  }
                | Command { return_to_main: true, ..  }
                | Decrypt { return_to_main: true, ..  }
                | ModifyEntryMeta
                | ModifyField { .. },
            ..
        }
        | SelectState::PopUp { .. } => (
            &[
                " ----- commands ----- ",
                "New entry:    ':new'",
                "Decrypt:      ':unlock'",
                "              ':decrypt'",
                "Delete entry: ':delete'",
                "Exit:         ':q(uit)'",
                "Force-exit:   ':q(uit)!'",
                "Write:        ':w(rite)'",
                "Write-exit:   ':wq'",
                " ---- single keys ---- ",
                "Exit:           'q'",
                "Search:         '/'",
                "Delete field:   'd'",
                "Swap encrypt:   's'",
                "Add field:      '+'",
                "Add TOTP field: 't'",
            ],
            &[
                " ---- movement ---- ",
                "up:    'k'",
                "down:  'j'",
                "left:  'h'",
                "right: 'l'",
            ],
        ),
        SelectState::Entries
        | SelectState::BottomCommand {
            kind: Search { return_to_main: false, ..  }
                | Command { return_to_main: false }
                | Decrypt { return_to_main: false, ..  },
            ..
        } => (
            &[
                " ---- commands ---- ",
                "New entry:  ':new'",
                "Decrypt:    ':unlock'",
                "            ':decrypt'",
                "Exit:       ':q(uit)'",
                "Force-exit: ':q(uit)!'",
                "Write:      ':w(rite)'",
                "Write-exit: ':wq'",
                " --- single keys --- ",
                "Exit:         'q'",
                "Search:       '/'",
            ],
            &[
                " --- movement --- ",
                "up:    'k'",
                "down:  'j'",
                "left:  'h'",
                "right: 'l'",
                "scroll up:   'Ctrl+y'",
                "scroll down: 'Ctrl+e'",
            ],
        ),
    };

    // We add 2 to include the borders at the top and bottom of the widget
    let include_moves = normal.len() + moves.len() + 2 <= rect.height as usize;

    let mut text: Vec<_> = normal
        .iter()
        .map(|&line| Spans::from(Span::raw(line)))
        .collect();
    if include_moves {
        text.extend(moves.iter().map(|&line| Spans::from(Span::raw(line))));
    }

    f.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .title("Keybindings/Commands")
                    .borders(Borders::ALL),
            )
            .alignment(Alignment::Left),
        rect,
    )
}

fn render_popup(
    f: &mut Frame,
    total_rect: Rect,
    header: &str,
    message: &[String],
    border_color: Color,
) {
    ////////////////////////////////////////////////////////////////////////////////
    // Step 1: Compute the internal area of the popup                             //
    ////////////////////////////////////////////////////////////////////////////////

    // +2 for borders, plus one for each line in `message`
    let height = message.len() as u16 + 2;
    let vert_margin = total_rect.height.saturating_sub(height) / 2;
    let vert = vertical_chunks(
        total_rect,
        vec![
            Constraint::Length(vert_margin),
            Constraint::Length(height),
            Constraint::Length(vert_margin),
        ],
    );

    // Once again, adding two for the margins
    let max_length = message
        .iter()
        .map(|line| line.len())
        .max()
        .unwrap_or_else(|| header.len());
    let width = max_length as u16 + 2;
    let horiz_margin = total_rect.width.saturating_sub(width) / 2;
    let horiz = horizontal_chunks(
        vert[1],
        vec![
            Constraint::Length(horiz_margin),
            Constraint::Length(width),
            Constraint::Length(horiz_margin),
        ],
    );

    // `rect` gives the final region for the pop-up
    let rect = horiz[1];

    ////////////////////////////////////////////////////////////////////////////////
    // Step 2: Render the pop-up into the given area                              //
    ////////////////////////////////////////////////////////////////////////////////

    let text = message
        .iter()
        .map(|line| textwrap::wrap(line, rect.width.saturating_sub(2) as usize))
        .flatten()
        .map(|line| Spans::from(Span::raw(line)))
        .collect::<Vec<_>>();
    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(header)
                .borders(Borders::ALL)
                .border_style(default_style().fg(border_color)),
        )
        .alignment(Alignment::Left);

    f.render_widget(widgets::Clear, rect);
    f.render_widget(paragraph, rect);
}
