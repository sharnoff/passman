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

There's two defined commands: creating a new `passman`-managed file with `passman --new <FILE>`, and
loading an existing one with `passman <FILE>`. The clip below shows some sample usage - just enough
to get you started.

[![asciicast](https://asciinema.org/a/rEDu5cvwwBk7r7dqeMSjJMvdc.svg)](https://asciinema.org/a/rEDu5cvwwBk7r7dqeMSjJMvdc)

This produces the file "test":
```yml
---
token: 7a0ORfcXbfQRuFCNOiiv50U9KxDHQbA5YQKLJ86VHwM=
iv: KnGbdjX8GavtUeZf7h8g2A==
last_update:
  secs_since_epoch: 1586116699
  nanos_since_epoch: 253419844
inner:
  - name: Test!
    tags: []
    fields:
      - name: Github
        value:
          Basic: github.com/sharnoff/passman
      - name: Password
        value:
          Protected: mm7ZVDxPfurj44UIyJsiEQ==
    first_added:
      secs_since_epoch: 1586116685
      nanos_since_epoch: 907506259
    last_update:
      secs_since_epoch: 1586116699
      nanos_since_epoch: 253419844
```

### Possible future features

* Better TUI - maybe using something like [tui](#https://github.com/fdehau/tui-rs)
* Operating over a network (or running as a daemon)
