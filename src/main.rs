use clap::{IntoApp, Parser};
use std::path::PathBuf;
use std::process::exit;

mod app;
mod subcmd;
mod ui;
mod utils;
mod version;

fn main() {
    let args = Args::parse();

    // We're expecting that EITHER:
    // * there's a subcommand, or
    // * we're given a file to open
    // If neither or both of these are present, that's an error.
    if args.subcmd.is_none() == args.file.is_none() {
        let _: Result<_, _> = Args::into_app().print_help();
        exit(1);
    }

    match args.subcmd {
        None => app::run(args.file.unwrap()),
        Some(Subcommand::New(args)) => subcmd::new::run(args),
        Some(Subcommand::Update(args)) => subcmd::update::run(args),
        Some(Subcommand::EmitPlaintext(args)) => subcmd::emit_plaintext::run(args),
        Some(Subcommand::FromPlaintext(args)) => subcmd::from_plaintext::run(args),
    }
}

#[derive(Parser)]
#[clap(
    version,
    author,
    about,
    // The 'ArgsNegateSubcommands' ensures that we either get 'file' or a subcommand, but not both.
    override_usage = "passman <FILE>  or  passman <SUBCOMMAND>",
)]
struct Args {
    #[clap(subcommand)]
    subcmd: Option<Subcommand>,

    /// The passwords file to read from (and write to)
    #[clap(name = "FILE")]
    file: Option<PathBuf>,
}

#[derive(clap::Subcommand)]
enum Subcommand {
    /// Initializes a new file for storing passwords
    #[clap(name = "new")]
    New(subcmd::new::Args),

    /// Converts old passman files to the current version
    ///
    /// To update in-place, provide the same value for both input and ouptut.
    #[clap(name = "update")]
    Update(subcmd::update::Args),

    /// Outputs a plaintext (fully decrypted) version of the file
    ///
    /// This can be used with the from-plaintext subcommand as a roundabout way of changing the
    /// password for a file. Remember to `shred` any plaintext files after you're done.
    ///
    /// See also: from-plaintext
    #[clap(name = "emit-plaintext")]
    EmitPlaintext(subcmd::emit_plaintext::Args),

    /// Creates a new file from a plaintext version
    ///
    /// This is really only expected to be used with the output of emit-plaintext, though manual
    /// editing or analysis might be useful in some cases.
    #[clap(name = "from-plaintext")]
    FromPlaintext(subcmd::from_plaintext::Args),
}
