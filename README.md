# passman

A simple terminal-based password (and associated information) manager. Nothing quite like
rolling your own, right?

**\[Disclaimer\]**: I know about as much about security as what a few google searches will offer.
You should **under no circumstances treat this seriously**. (That being said, contents *are*
encrypted with 256-bit AES -- feel free to check for yourself.)

With that out of the way, contributions are definitely welcome! This was a few-days project to
satisfy a personal desire, but I'd be happy to invest more effort into growing it if there's
interest - just open an issue or pull request, nothing too fancy.

### Installation

This is a simple sort of thing, so I didn't view it as worthy of taking a name on crates.io. If
there's a desire for it to be added, it can.

For now, installing can be done by cargo via git.
```
cargo install --git "https://github.com/sharnoff/passman.git"
```
This provides the executable `passman`. I use this with an alias, "pm" that executes this on a
persistent file.

### Usage

There's a few defined commands. Typical usage for interacting with a storage file will be done with
`passman <FILE>`. A new file can be made with `passman new <FILE>`, or upgraded from a previous
version with `passman upgrade --input <FILE> --output <FILE>`. The right-hand side of the app
provides help with keybindings.
