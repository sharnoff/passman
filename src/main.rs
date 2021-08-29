use std::process::exit;

mod app;
mod subcmd;
mod ui;
mod utils;
mod version;

fn main() {
    let matches = clap_app().get_matches();

    // We're expecting that EITHER:
    // * there's a subcommand, or
    // * we're given a file to open
    // If neither or both of these are present, that's an error.
    if matches.subcommand().is_some() == matches.value_of("FILE").is_some() {
        let _: Result<_, _> = clap_app().print_help();
        exit(1);
    }

    match matches.subcommand() {
        Some(("new", ms)) => subcmd::new::run(ms),
        Some(("update", ms)) => subcmd::update::run(ms),
        _ => app::run(&matches),
    }
}

fn clap_app() -> clap::App<'static> {
    use clap::clap_app;

    clap_app!(passman =>
        (version: "0.3")
        (author: "Max Sharnoff <passman@max.sharnoff.org>")
        (about: "A simple, terminal-based password manager")
        (override_usage: "passman <FILE>  or  passman <SUBCOMMAND>")
        (@subcommand new =>
            (about: "Initializes a new file for storing passwords")
            (@arg FILE: +required "Sets the file to write to")
        )
        (@subcommand update =>
            (about: "Converts old passman files to the current version")
            (@arg INPUT: -i --input +required +takes_value "Sets the input file to read from")
            (@arg OUTPUT: -o --output +required +takes_value "Sets the output file to write to")
        )
        (@arg FILE: "The passwords file to read from (and write to)")
    )
}
