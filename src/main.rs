use std::io::{self, Stdout};
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
    for res in io::stdin().events() {
        if !app.handle(res?) {
            terminal.clear()?;
            break;
        }

        ui::draw(&mut terminal, &app)?;
    }

    Ok(())
}
