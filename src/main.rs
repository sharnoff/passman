use signal_hook::{iterator::Signals, SIGWINCH};
use std::io::{self, Stdout};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use termion::event::Event;
use termion::input::TermRead;
use termion::raw::{IntoRawMode, RawTerminal};
use tui::backend::TermionBackend;

mod app;
mod crypt;
mod ui;
mod utils;

use app::App;

const ENCRYPT_TOKEN: &str = "encryption token ☺";

type Backend = TermionBackend<RawTerminal<Stdout>>;
type Terminal = tui::Terminal<Backend>;

fn main() -> Result<(), io::Error> {
    // We construct the app before any terminal setup so that any possible errors will display
    // nicely
    let clap_yaml = clap::load_yaml!("clap.yml");
    let mut app = match App::new(clap::App::from(clap_yaml)) {
        Some(app) => app?,
        None => return Ok(()),
    };

    // A little bit of setup:
    let stdout = io::stdout().into_raw_mode()?;
    let backend = TermionBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    ui::draw(&mut terminal, &app)?;

    // And then we simply run all while we have key inputs
    for item in events()? {
        if let Some(event) = item {
            if !app.handle(event?) {
                terminal.clear()?;
                break;
            }
        }

        ui::draw(&mut terminal, &app)?;
    }

    Ok(())
}

// Produces an iterator over all of the terminal events
//
// This is essentially a wrapper around stdin().events() to additionally give resizes as an event,
// so we return None if it was a resize.
fn events() -> io::Result<impl Iterator<Item = Option<io::Result<Event>>>> {
    // In order to do this properly, we need multiple threads to handle
    struct Iter {
        rx: Receiver<Option<io::Result<Event>>>,
    }

    impl Iterator for Iter {
        type Item = Option<io::Result<Event>>;

        fn next(&mut self) -> Option<Self::Item> {
            self.rx.recv().ok()
        }
    }

    let (tx, rx) = channel();
    let iter = Iter { rx };

    // We'll spawn two threads to handle sending into the channel. The first will produce events
    // from resizes:
    let signals = Signals::new(&[SIGWINCH])?;
    let tx_cloned = tx.clone();
    thread::spawn(move || {
        for _ in &signals {
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
