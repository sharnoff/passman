//! Display handling for application state

use crate::app::{App, CommandKind, EntrySelectState, SelectState, Value};
use crate::utils;
use crate::{Backend, Terminal};
use std::io;
use std::sync::atomic::Ordering::SeqCst;
use tui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans};
use tui::widgets::{self, Block, Borders, Paragraph};

type Frame<'a> = tui::terminal::Frame<'a, Backend>;

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

pub fn draw(term: &mut Terminal, app: &App) -> Result<(), io::Error> {
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
    })
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
    let title = match app.search_filter.as_ref() {
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

    let entries_list: Vec<_> = match app.filter.as_ref() {
        // If there's no filter, we can just provide the entries as is
        None => app.entries.inner[start_row..].iter().collect(),
        Some(list) => list.iter().map(|&i| &app.entries.inner[i]).collect(),
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
        .into_iter()
        .enumerate()
        .map(|(i, e)| {
            let style = match selected_row == Some(i) {
                true => Style::default().fg(Color::Black).bg(Color::Blue),
                false => Style::default(),
            };

            Spans::from(Span::styled(&e.name, style))
        })
        .collect();

    let paragraph = Paragraph::new(text).block(block).alignment(Alignment::Left);
    f.render_widget(paragraph, rect);

    // We subtract 2 from the height because it has borders on both sides
    if let Some(height) = rect.height.checked_sub(2) {
        app.last_entries_height.store(height as usize, SeqCst);
    }
}

fn render_cmd(f: &mut Frame, rect: Rect, app: &App) {
    let title = match &app.selected {
        SelectState::BottomCommand { kind, .. } => match kind {
            CommandKind::Search { .. } => "Searching entries",
            CommandKind::Command { .. } => "Command input",
            CommandKind::ModifyEntry { name } => match app.main_selected {
                EntrySelectState::Name => "Editing entry name",
                EntrySelectState::Tags => "Editing entry tags",
                EntrySelectState::Field { .. } => match name {
                    None => "Editing field name",
                    Some(_) => "Editing field value",
                },
                EntrySelectState::Plus => match name {
                    None => "New field name",
                    Some(_) => "New field value",
                },
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
        Some(idx) => &app.entries.inner[idx],
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

    let mut text = Vec::with_capacity(entry.fields.len() + 5);
    text.push(styled(
        "",
        "Entry name: ",
        format!("{:?}", entry.name),
        selected == Some(Name),
    ));
    text.push(styled(
        "",
        "Tags: ",
        utils::comma_strings(&entry.tags),
        selected == Some(Tags),
    ));

    for (idx, field) in entry.fields.iter().enumerate() {
        let is_selected = selected == Some(Field { idx });
        let value = match (&field.value, is_selected) {
            (Value::Protected(_), false) => "<Protected>".into(),
            _ => field
                .value
                .format(app.key.as_ref(), app.entries.iv.as_ref()),
        };

        let prefix = match field.value {
            Value::Basic(_) => "  ",
            Value::Protected(_) => "🔒",
        };

        text.push(styled(
            prefix,
            format!("{}: ", field.name),
            value,
            selected == Some(Field { idx }),
        ));
    }

    text.push(styled("", "", "[+]", selected == Some(Plus)));
    text.push(Spans::from(Span::raw("")));

    text.push(Spans::from(Span::raw(format!(
        "First added: {}",
        utils::format_time(entry.first_added)
    ))));
    if entry.last_update != entry.first_added {
        text.push(Spans::from(Span::raw(format!(
            "Last updated: {}",
            utils::format_time(entry.last_update)
        ))));
    }

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(format!("Selected {:?}", entry.name))
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

    let decrypted = format!("{} Decrypted", status_char(app.key.is_some()));
    let unsaved = format!("{} Unsaved", status_char(app.unsaved));

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
    use CommandKind::{Command, Decrypt, ModifyEntry, Search};
    use SelectState::{BottomCommand, Entries, Main, PopUp};

    let (normal, moves): (&[_], &[_]) = match app.selected {
        Main
        | BottomCommand {
            kind: Search {
                return_to_main: true,
                ..
            },
            ..
        }
        | BottomCommand {
            kind: Command {
                return_to_main: true,
            },
            ..
        }
        | BottomCommand {
            kind: Decrypt {
                return_to_main: true,
                ..
            },
            ..
        }
        | BottomCommand {
            kind: ModifyEntry { .. },
            ..
        }
        | PopUp { .. } => (
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
                "Exit:          'q'",
                "Search:        '/'",
                "Delete field:  'd'",
                "Swap encrypt:  's'",
                "Add field:     '+'",
            ],
            &[
                " ---- movement ---- ",
                "up:    'k'",
                "down:  'j'",
                "left:  'h'",
                "right: 'l'",
            ],
        ),
        Entries
        | BottomCommand {
            kind: Search {
                return_to_main: false,
                ..
            },
            ..
        }
        | BottomCommand {
            kind: Command {
                return_to_main: false,
            },
            ..
        }
        | BottomCommand {
            kind: Decrypt {
                return_to_main: false,
                ..
            },
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
        .map(|line| textwrap::wrap_iter(line, rect.width.saturating_sub(2) as usize))
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
