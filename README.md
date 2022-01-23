# passman

A simple terminal-based password (and associated information) manager. There are plenty of others
available, and - to be honest - there isn't really any reason you should use this one instead of
them.

That being said, the user-interface feels great and the project is generally pretty simple!
Contributions are welcome :)

### Installation

This is a simple sort of thing, so I didn't view it as worthy of taking a name on crates.io. If
there's a desire for it to be added, it can.

For now, installing can be done by cargo via git.
```
cargo install --git "https://github.com/sharnoff/passman"
```
This provides the executable `passman`. I use this with an alias, "pm" that runs this on the
particular file I keep everything in.

### Usage

There's a few basic commands available.

To set up a new file, use `passman new <FILE>`.

All changes to data are done using the simple `passman <FILE>` command. The app itself uses vi-style
keybindings - a list of available commands is on the right-hand side at all times.

Updating an old file can be done with `passman upgrade --input <OLD FILE> --output <NEW FILE>`, and
there's additional support for producing and using plaintext versions, with the `emit-plaintext` and
`from-plaintext` subcommands.

## TOTP Fields

In addition to regular values, `passman` also supports TOTP fields (like Google Authenticator). The
values must currently be entered manually; plenty of guides for extracting the secret keys can be
found online. I have personally used https://github.com/scito/extract_otp_secret_keys after
exporting keys from Google Authenticator; I'd assume a similar method would work for new keys as
well.
