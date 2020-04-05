#![deny(unused_must_use)]
// #![deny(unused_imports)]
#![deny(mutable_borrow_reservation_conflict)]

use std::fmt::{self, Display};
use std::fs::{self, File};
use std::io::{stdin, stdout, Write};
use std::process;
use std::time::SystemTime;

use clap::App;
use fuzzy_matcher::{skim::SkimMatcherV2, FuzzyMatcher};
use serde::{de::Error, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

mod utils;

const ENCRYPT_TOKEN: &str = "encryption token ☺";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entries {
    // The token of the encryption - just to know if it was correct
    // TODO: This should be done properly, not how it is currently.
    token: Base64Vec,
    // This should be done properly as well.
    // I haven't done the necessary research to know the best practice here.
    iv: Base64Vec,
    last_update: SystemTime,
    inner: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    name: String,
    tags: Vec<String>,
    fields: Vec<Field>,
    first_added: SystemTime,
    last_update: SystemTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Field {
    name: String,
    value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Value {
    Protected(Base64Vec),
    Basic(String),
}

#[derive(Debug, Clone)]
struct Base64Vec(Vec<u8>);

macro_rules! flush {
    () => {
        stdout().flush().unwrap();
    };
}

fn main() {
    let yaml = clap::load_yaml!("clap.yml");
    let matches = App::from(yaml).get_matches();

    let file_name = matches.value_of("FILE").unwrap();

    if matches.is_present("new") {
        create_new(file_name);
        return;
    }

    // Otherwise, we're just doing normal things...
    let input = fs::read_to_string(file_name).unwrap();
    let entries = serde_yaml::from_str(&input).unwrap();

    run_interactive(entries, file_name);
}

fn create_new(file_name: &str) {
    let mut file = File::create(file_name).unwrap();

    println!("Please enter an encryption key:");

    let pwd = utils::read_password();
    let iv = utils::gen_iv();
    let token = utils::encrypt_with(&pwd, ENCRYPT_TOKEN.as_ref(), &iv);

    let entries = Entries {
        token: Base64Vec(token),
        iv: Base64Vec(Vec::from(iv.as_ref())),
        last_update: SystemTime::now(),
        inner: Vec::new(),
    };

    let s = serde_yaml::to_string(&entries).unwrap();
    write!(file, "{}", s).unwrap();
    file.flush().unwrap();
    println!(
        "Generation successful! Wrote {} bytes to '{}'",
        s.len(),
        file_name
    );
}

struct Context<'a> {
    entries: Entries,
    filter: Vec<usize>,
    unsaved: bool,
    key: Option<String>,
    file_name: &'a str,
}

fn run_interactive(entries: Entries, file_name: &str) {
    println!("Loaded info from file {:?}.", file_name);
    println!("Last update: {}", utils::format_time(entries.last_update));

    let mut ctx = Context {
        entries,
        filter: Vec::new(),
        unsaved: false,
        key: None,
        file_name,
    };

    enum Cmd {
        Decrypt,
        List,
        Search,
        Add,
        Write,
        Quit,
    }

    use Cmd::*;

    loop {
        println!("\nPlease enter a command [(d)ecrypt/(l)ist/(s)earch/(a)dd/(w)rite/(q)uit]");
        print!(">> ");
        flush!();
        let cmd = utils::read_valid(|s| {
            match s.to_lowercase().as_ref() {
                "d" | "decrypt" => Ok(Cmd::Decrypt),
                "l" | "list" => Ok(Cmd::List),
                "s" | "search" => Ok(Cmd::Search),
                "a" | "add" => Ok(Cmd::Add),
                "w" | "write" => Ok(Cmd::Write),
                "q" | "quit" => Ok(Cmd::Quit),
                _ => Err(
                    "Invalid command. Please enter one of [(d)ecrypt/(l)ist/(s)earch/(a)dd/(w)rite/(q)uit]\n>> "
                ),
            }
        });

        match cmd {
            Decrypt => drop(try_decrypt(&mut ctx)),
            List => list(&ctx.entries),
            Search => search(&mut ctx),
            Add => drop(add_entry(&mut ctx)),
            Write => try_write(&mut ctx),
            Quit => try_quit(ctx.unsaved),
        }
    }
}

// Prompts the user to enter the decryption key, and continues doing so until it is valid or they
// quit. Returns whether the correct key was given.
fn try_decrypt(ctx: &mut Context) -> bool {
    if ctx.key.is_some() {
        println!("You've already decrypted the protected contents!");
        return true;
    }

    loop {
        println!("Please enter the decryption key:");
        let new_key = utils::read_password();

        // check whether it was a valid key
        let cipher_token = ctx.entries.token.as_ref();
        let iv = ctx.entries.iv.as_ref();
        let decrypted_token = utils::decrypt_with(&new_key, cipher_token, iv);

        if let Some(t) = decrypted_token {
            if &t == &ENCRYPT_TOKEN.as_bytes() {
                ctx.key = Some(new_key);
                println!("Decryption successful.");
                return true;
            }
        }

        print!("Failed to decrypt. Try again? [Y/n] ");
        flush!();
        if !utils::query_yes_no() {
            return false;
        }
    }
}

fn list(entries: &Entries) {
    if entries.inner.is_empty() {
        println!("No entries to display");
        return;
    }

    entries.inner.iter().for_each(|e| println!("{}", e));
}

fn search(ctx: &mut Context) {
    #[derive(PartialEq)]
    enum Cmd {
        List,
        Select(usize),
        Refine,
        Exit,
    }

    use Cmd::*;

    ctx.filter = (0..ctx.entries.inner.len()).collect();
    let mut last_cmd = None as Option<Cmd>;

    loop {
        if last_cmd.is_none() || last_cmd == Some(Refine) {
            print!("Enter a key to search by:\n>> ");
            flush!();
            let key =
                utils::read_nonempty_string("Please enter a non-empty key to search by:\n>> ");

            let results_idxs = ctx.search(&key);
            if results_idxs.is_empty() {
                println!("No results");
                if last_cmd.is_none() {
                    return;
                }
            } else {
                ctx.filter = results_idxs;
                ctx.print_filter();
            }
        } else if last_cmd == Some(List) {
            ctx.print_filter();
        }

        if ctx.filter.len() == 1 {
            let idx = ctx.filter[0];
            focus_entry(ctx, idx);
            return;
        }

        print!(
            "\nEnter a search command [(l)ist/(r)efine/e(x)it] or a number to select an entry\n>> "
        );
        flush!();
        let cmd = utils::read_valid(|s| match s.to_lowercase().as_ref() {
            "l" | "list" => Ok(List),
            "r" | "refine" => Ok(Refine),
            "x" | "exit" => Ok(Exit),
            s => {
                if let Ok(n) = s.parse() {
                    if ctx.filter.contains(&n) {
                        return Ok(Select(n));
                    }
                }

                Err("Please enter one of [(l)ist/(s)elect/(r)efine/e(x)it] or a number to select an entry\n>> ")
            }
        });

        match cmd {
            Exit => break,
            Select(n) => {
                focus_entry(ctx, n);
                return;
            }
            _ => (),
        }

        last_cmd = Some(cmd);
    }
}

fn focus_entry(ctx: &mut Context, n: usize) {
    let len = ctx.entries.inner.len();
    if n >= len {
        panic!(
            "Index out of bounds: ctx.entries.inner.len() = {}, n = {}",
            len, n
        );
    }

    enum Cmd {
        View,
        Edit,
        Delete,
        Exit,
    }

    use Cmd::*;

    loop {
        println!("Selected entry {}: '{}'", n, ctx.entries.inner[n].name);
        print!("What would you like to do? [(v)iew/(e)dit/(d)elete/e(x)it]\n>> ");
        flush!();

        let cmd = utils::read_valid(|s| match s.to_lowercase().as_ref() {
            "v" | "view" => Ok(View),
            "e" | "edit" => Ok(Edit),
            "d" | "delete" => Ok(Delete),
            "x" | "exit" => Ok(Exit),
            _ => Err("Please enter one of [(v)iew/(e)dit/e(x)it]\n>> "),
        });

        match cmd {
            View => view_entry(ctx, n, false),
            Edit => {
                edit_entry(ctx, n);
                // We return here because all operations here are available from the editing mode.
                return;
            }
            Exit => return,
            Delete => {
                // Remove the entry
                ctx.entries.inner.remove(n);
                ctx.filter = ctx
                    .filter
                    .iter()
                    .filter_map(|&f| {
                        if f > n {
                            Some(f - 1)
                        } else if f < n {
                            Some(f)
                        } else {
                            None
                        }
                    })
                    .collect();
                return;
            }
        }
    }
}

fn view_entry(ctx: &mut Context, idx: usize, display_field_idxs: bool) {
    if ctx.key.is_none()
        && ctx.entries.inner[idx]
            .fields
            .iter()
            .any(Field::is_protected)
    {
        println!("This entry has protected fields. Please decrypt to view.");
        if !try_decrypt(ctx) {
            return;
        }
    }

    let entry = &ctx.entries.inner[idx];
    match ctx.key.as_ref() {
        None => println!("{}", entry),
        Some(k) => entry.print_decrypted(k, ctx.entries.iv.as_ref(), display_field_idxs),
    }
}

fn edit_entry(ctx: &mut Context, idx: usize) {
    let mut print_help = true;
    let mut print_entry_name = true;

    loop {
        if print_entry_name {
            println!("Editing entry {}: '{}'", idx, ctx.entries.inner[idx].name);
            print_entry_name = false;
        }

        if print_help {
            const HELP_STR: &'static str =
                "Many commands are available here, some of which have special syntax.
These are listed below:
* (t)ags - allows editing the tags of the entry
* (f)ield - edits a single field. Usage: `f<field number>`
* (a)dd (b)asic - prompts for adding a basic field. Usage: `ab`
* (a)dd (p)rotected - prompts for adding a protected field. Usage: `ap`
* (r)ename a field. Usage: `r<field number>`
* (d)elete a field. Usage: `d<field number>`
* (v)iew the entry
* e(x)it
* (h)elp - display this information\n";

            println!("{}", HELP_STR);
            print_help = false;
        }

        print!(">> ");
        flush!();

        enum Cmd {
            Tags,
            Field(usize),
            Add(FieldKind),
            Rename(usize),
            Delete(usize),
            View,
            Exit,
            Help,
        }

        use Cmd::*;

        let cmd = utils::read_valid(|inp| {
            let s = inp.to_lowercase();
            if s.is_empty() {
                return Err("Please enter one of [t/f/a/r/d/v/x] or 'h' for help\n>> ");
            }

            match s.chars().take(1).next().unwrap() {
                't' | 'f' | 'a' | 'r' | 'd' | 'v' | 'x' | 'h' => (),
                _ => return Err("Please enter one of [t/f/a/r/d/v/x] or 'h' for help\n>> "),
            }

            match s.as_ref() {
                "t" | "tag" | "tags" => Ok(Tags),
                "ab" | "add basic" => Ok(Add(FieldKind::Basic)),
                "ap" | "add protected" => Ok(Add(FieldKind::Protected)),
                "v" | "view" => Ok(View),
                "x" | "exit" => Ok(Exit),
                "h" | "help" => Ok(Help),
                s => {
                    let n = match s[1..].parse() {
                        Ok(n) => n,
                        Err(_) => {
                            return Err("Please enter one of [t/f/a/r/d/v/x] or 'h' for help\n>> ")
                        }
                    };

                    if n >= ctx.entries.inner[idx].fields.len() {
                        return Err("Field index out of bounds. Please enter a different one");
                    }

                    match s.chars().take(1).next().unwrap() {
                        'f' => Ok(Field(n)),
                        'r' => Ok(Rename(n)),
                        'd' => Ok(Delete(n)),
                        _ => Err("Please enter one of [t/f/a/r/d/v/x] or 'h' for help\n>> "),
                    }
                }
            }
        });

        let changed = match cmd {
            Tags => change_tags(&mut ctx.entries.inner[idx]),
            Field(i) => edit_field(ctx, idx, i),
            Add(kind) => add_field(ctx, idx, kind),
            Rename(i) => rename_field(&mut ctx.entries.inner[idx], i),
            // Deletes a *field*
            Delete(i) => {
                ctx.entries.inner[idx].fields.remove(i);
                true
            }
            View => {
                view_entry(ctx, idx, true);
                false
            }
            Exit => return,
            Help => {
                print_help = true;
                false
            }
        };

        if changed {
            let now = SystemTime::now();
            ctx.entries.inner[idx].last_update = now;
            ctx.entries.last_update = now;
            ctx.unsaved = true;
        }
    }
}

#[derive(PartialEq)]
enum FieldKind {
    Basic,
    Protected,
}

fn change_tags(entry: &mut Entry) -> bool {
    println!(
        "The current tags are: {}",
        utils::comma_strings(&entry.tags)
    );
    println!("Please enter alternate ones, separated by commas (or enter none):");
    print!(">> ");
    flush!();

    let mut input = String::new();
    stdin().read_line(&mut input).unwrap();
    let new_tags = input.split(',').map(|s| s.trim().into()).collect();
    if new_tags != entry.tags {
        entry.tags = new_tags;
        true
    } else {
        false
    }
}

fn edit_field(ctx: &mut Context, entry_idx: usize, field_idx: usize) -> bool {
    let field_is_protected =
        |c: &Context| c.entries.inner[entry_idx].fields[field_idx].is_protected();
    let set_value =
        |c: &mut Context, v: Value| c.entries.inner[entry_idx].fields[field_idx].value = v;

    println!(
        "Editing field {:?}.",
        ctx.entries.inner[entry_idx].fields[field_idx].name
    );

    enum Cmd {
        Modify,
        SwitchEncrypted,
        Exit,
    }

    use Cmd::*;

    let mut changed = false;

    loop {
        match field_is_protected(ctx) {
            true => println!("Please enter a command [(m)odify/d(e)crypt/e(x)it]"),
            false => println!("Please enter a command [(m)odify/(e)ncrypt/e(x)it]"),
        }
        print!(">> ");
        flush!();

        let cmd = utils::read_valid(|s| match s.to_lowercase().as_ref() {
            "m" | "modify" => Ok(Modify),
            "e" => Ok(SwitchEncrypted),
            "decrypt" if field_is_protected(ctx) => Ok(SwitchEncrypted),
            "encrypt" if field_is_protected(ctx) => Ok(SwitchEncrypted),
            "x" | "exit" => Ok(Exit),
            _ => Err("Invalid comand. Please enter one of [(m)odify/(e)ncrypt/e(x)it]\n>> "),
        });

        match cmd {
            Exit => return changed,
            SwitchEncrypted => {
                if ctx.key.is_none() {
                    match field_is_protected(ctx) {
                        true => println!(
                            "To decrypt this protected field, you must provide the key first."
                        ),
                        false => {
                            println!("To encrypt this basic field, you must provide the key first.")
                        }
                    }

                    if !try_decrypt(ctx) {
                        println!("Unable to switch encryption status of field");
                        return changed;
                    }
                }

                let field_value = &ctx.entries.inner[entry_idx].fields[field_idx].value;
                let new_value = match field_value {
                    Value::Basic(v) => Value::Protected(Base64Vec(utils::encrypt_with(
                        ctx.key.as_ref().unwrap(),
                        v.as_bytes(),
                        ctx.entries.iv.as_ref(),
                    ))),
                    Value::Protected(p) => Value::Basic(
                        String::from_utf8(
                            utils::decrypt_with(
                                ctx.key.as_ref().unwrap(),
                                p.as_ref(),
                                ctx.entries.iv.as_ref(),
                            )
                            .unwrap(),
                        )
                        .unwrap(),
                    ),
                };

                set_value(ctx, new_value);
                changed = true;
            }
            Modify => {
                if !field_is_protected(ctx) {
                    print!("New value? ");
                    flush!();
                    set_value(
                        ctx,
                        Value::Basic(utils::read_nonempty_string(
                            "Please enter a non-empty value: ",
                        )),
                    );
                } else {
                    if ctx.key.is_none() {
                        println!("To modify this protected field, you must decrypt first.");
                        if !try_decrypt(ctx) {
                            println!("Unable to modify protected field");
                            return changed;
                        }
                    }

                    let pwd = loop {
                        println!("Protected value?");
                        let first = utils::read_password();
                        println!("Enter again to confirm:");
                        let second = utils::read_password();

                        if first != second {
                            println!("The values didn't match!");
                            print!("Try again? [Y/n] ");
                            flush!();
                            if !utils::query_yes_no() {
                                return changed;
                            }
                        }

                        break first;
                    };

                    let p = utils::encrypt_with(
                        ctx.key.as_ref().unwrap(),
                        pwd.as_bytes(),
                        ctx.entries.iv.as_ref(),
                    );
                    set_value(ctx, Value::Protected(Base64Vec(p)));
                }

                changed = true;
            }
        }
    }
}

fn add_field(ctx: &mut Context, idx: usize, field_kind: FieldKind) -> bool {
    if field_kind == FieldKind::Protected && ctx.key.is_none() {
        println!("To add a protected field to this entry, you must decrypt first.");
        if !try_decrypt(ctx) {
            println!("Unable to add protected field");
            return false;
        }
    }

    let entry = &mut ctx.entries.inner[idx];
    let name = loop {
        print!("Field name? ");
        flush!();
        let name = utils::read_nonempty_string("Please enter a non-empty name: ");

        if entry.fields.iter().find(|f| f.name == name).is_some() {
            println!("There's already a field with that name.");
            print!("Continue with a different name? [Y/n] ");
            flush!();

            if !utils::query_yes_no() {
                println!("Unable to add field; name already exists");
                return false;
            }

            continue;
        }

        break name;
    };

    let value = match field_kind {
        FieldKind::Basic => {
            print!("Value? ");
            flush!();
            Value::Basic(utils::read_nonempty_string(
                "Please enter a non-empty value: ",
            ))
        }
        FieldKind::Protected => {
            let pwd = loop {
                println!("Protected value?");
                let first = utils::read_password();
                println!("Enter again to confirm:");
                let second = utils::read_password();

                if first != second {
                    println!("The values didn't match!");
                    print!("Try again? [Y/n] ");
                    flush!();
                    if !utils::query_yes_no() {
                        return false;
                    }
                }

                break first;
            };

            let p = utils::encrypt_with(
                ctx.key.as_ref().unwrap(),
                pwd.as_bytes(),
                ctx.entries.iv.as_ref(),
            );
            Value::Protected(Base64Vec(p))
        }
    };

    entry.fields.push(Field { name, value });
    true
}

fn rename_field(entry: &mut Entry, field_idx: usize) -> bool {
    let name = loop {
        println!("Renaming field '{}'", entry.fields[field_idx].name);
        print!("Please enter the new field name:\n>> ");
        flush!();
        let name = utils::read_nonempty_string("Please enter a non-empty field name\n>> ");

        if entry.fields.iter().find(|f| f.name == name).is_some() {
            println!("There's already a field with that name.");
            print!("Continue (and pick a different one)? [Y/n] ");
            flush!();
            if !utils::query_yes_no() {
                return false;
            }

            continue;
        }

        break name;
    };

    entry.fields[field_idx].name = name;
    true
}

fn add_entry(ctx: &mut Context) -> bool {
    if ctx.key.is_none() {
        println!("Warning: You have not decrypted the contents yet.");
        println!("If you would like to add protected fields to this entry, you must decrypt.");
        print!("Would you like to decrypt now? [Y/n]\n>> ");
        flush!();
        if utils::query_yes_no() && !try_decrypt(ctx) {
            // Failed to decrypt - do they still want to continue?
            print!("Do you still want to add an entry? [Y/n]\n>> ");
            flush!();
            if !utils::query_yes_no() {
                return false;
            }
        }
    }

    // try to get the name -- we won't allow duplicates.
    let name = loop {
        print!("Entry name? ");
        flush!();
        let name = utils::read_nonempty_string("Please enter a non-empty name: ");

        if ctx.entries.inner.iter().find(|e| e.name == name).is_some() {
            println!("There's already an entry with that name.");
            println!("You must pick a different one. Would you still like to add an entry?");
            print!("[Y/n] >> ");
            flush!();

            if !utils::query_yes_no() {
                return false;
            }
        }

        break name;
    };

    let now = SystemTime::now();
    let new_entry = Entry {
        name,
        tags: Vec::new(),
        fields: Vec::new(),
        first_added: now,
        last_update: now,
    };

    ctx.entries.inner.push(new_entry);
    ctx.entries.last_update = now;
    ctx.unsaved = true;

    let idx = ctx.entries.inner.len() - 1;
    println!("");
    edit_entry(ctx, idx);

    true
}

fn try_write(ctx: &mut Context) {
    if !ctx.unsaved {
        println!("You have no unsaved changes. Do you still want to write to file?");
        print!("[Y/n] >> ");
        flush!();
        if !utils::query_yes_no() {
            return;
        }
    }

    // Try to open the file
    let mut f = match File::create(ctx.file_name) {
        Ok(f) => f,
        Err(e) => {
            println!("Failed to open file {:?}: {}", ctx.file_name, e);
            return;
        }
    };

    let s = serde_yaml::to_string(&ctx.entries).unwrap();

    if let Err(e) = write!(f, "{}", s).and_then(|_| f.flush()) {
        println!("Failed to write to file {:?}: {}", ctx.file_name, e);
        return;
    }
    ctx.unsaved = false;

    println!("Wrote {} bytes to file {:?}", s.len(), ctx.file_name);
}

fn try_quit(has_unsaved_changes: bool) {
    if has_unsaved_changes {
        print!("You have unsaved changes. Do you still want to quit? [Y/n]\n>> ");
        flush!();
        if !utils::query_yes_no() {
            return;
        }
    }

    process::exit(0);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper traits / methods                                                                        //
////////////////////////////////////////////////////////////////////////////////////////////////////

impl Entry {
    fn fuzzy_match(&self, matcher: &SkimMatcherV2, target: &str) -> Option<i64> {
        self.tags
            .iter()
            .map(|t| matcher.fuzzy_match(t, target))
            .max()
            .unwrap_or_default()
            .max(matcher.fuzzy_match(&self.name, target))
    }

    // TODO: refactor this and the Display implementation
    fn print_decrypted(&self, key: &str, iv: &[u8], display_field_idxs: bool) {
        println!("{}", self.name);
        println!("    Tags: {}", utils::comma_strings(&self.tags));
        println!("    First added:  {}", utils::format_time(self.first_added));
        println!("    Last updated: {}", utils::format_time(self.last_update));
        for (i, f) in self.fields.iter().enumerate() {
            if display_field_idxs {
                println!("    ({}) {}", i, f.to_string_decrypted(key, iv));
            } else {
                println!("    {}", f.to_string_decrypted(key, iv));
            }
        }
    }
}

impl Display for Entry {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        writeln!(fmt, "{}", self.name)?;
        writeln!(fmt, "    Tags: {}", utils::comma_strings(&self.tags))?;
        writeln!(
            fmt,
            "    First added:  {}",
            utils::format_time(self.first_added)
        )?;
        writeln!(
            fmt,
            "    Last updated: {}",
            utils::format_time(self.last_update)
        )?;
        for f in self.fields.iter() {
            writeln!(fmt, "    {}", f)?;
        }

        Ok(())
    }
}

impl Field {
    fn to_string_decrypted(&self, key: &str, iv: &[u8]) -> String {
        match &self.value {
            Value::Basic(s) => format!("{}: {}", self.name, s),
            Value::Protected(p) => {
                let s = String::from_utf8(utils::decrypt_with(key, &p.0, iv).unwrap()).unwrap();
                format!("{}: {}", self.name, s)
            }
        }
    }
}

impl Display for Field {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}: {}", self.name, self.value)
    }
}

impl Field {
    fn is_protected(&self) -> bool {
        match self.value {
            Value::Basic(_) => false,
            Value::Protected(_) => true,
        }
    }
}

impl Display for Value {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Value::Protected(_) => "<Protected>",
            Value::Basic(s) => s.as_ref(),
        };

        write!(fmt, "{}", s)
    }
}

impl AsRef<[u8]> for Base64Vec {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Base64Vec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = base64::encode(&self.0);
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for Base64Vec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(Base64VecVisitor)
    }
}

struct Base64VecVisitor;

impl<'de> Visitor<'de> for Base64VecVisitor {
    type Value = Base64Vec;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a base64-encoded string")
    }

    fn visit_str<E: Error>(self, s: &str) -> Result<Base64Vec, E> {
        base64::decode(s).map(Base64Vec).map_err(E::custom)
    }
}

impl<'a> Context<'a> {
    fn search(&self, target: &str) -> Vec<usize> {
        let matcher = SkimMatcherV2::default();

        let mut matches = self
            .filter
            .iter()
            .map(|&i| (i, self.entries.inner[i].fuzzy_match(&matcher, target)))
            .filter(|(_, score)| score.is_some())
            .collect::<Vec<(usize, Option<i64>)>>();

        // sort in reverse order.
        matches.sort_by_key(|(_, opt)| opt.map(|s| -s));

        matches.into_iter().map(|(i, _)| i).collect()
    }

    fn print_filter(&self) {
        for (i, e) in self.filter.iter().map(|&i| (i, &self.entries.inner[i])) {
            println!("({}) {}", i, e);
        }
    }
}
