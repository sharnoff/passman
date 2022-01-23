//! Various standalone utilities and helper functions

use chrono::{DateTime, Local};
use lazy_static::lazy_static;
use serde::{de::Error, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::fmt;
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

pub fn format_time(time: SystemTime) -> String {
    let time: DateTime<Local> = time.into();
    time.to_rfc2822()
}

pub fn comma_strings<S: AsRef<str>>(strs: &[S]) -> String {
    if strs.is_empty() {
        return "<None>".into();
    }

    let mut result: String = strs[0].as_ref().into();
    for s in strs[1..].iter() {
        result.push(',');
        result.push_str(s.as_ref());
    }
    result
}

pub fn escape_quotes(s: &str) -> Cow<str> {
    match s.contains('"') {
        true => Cow::Owned(s.replace('"', "\"")),
        false => Cow::Borrowed(s),
    }
}

/// A wrapper around a `Vec<u8>` so that we can serialize and deserialize it as base-64 encoded
#[derive(Debug, Clone)]
pub struct Base64Vec(pub Vec<u8>);

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

lazy_static! {
    static ref TIMER_THREAD_TX: Mutex<mpsc::Sender<()>> = Mutex::new(make_timer_thread());
}

/// Orchestrates sending a timer tick after one second, signalling the app to refresh
pub fn send_refresh_tick_after_1_second() {
    let _ = TIMER_THREAD_TX.lock().unwrap().send(());
}

fn make_timer_thread() -> mpsc::Sender<()> {
    let (tx, rx) = mpsc::channel();

    let signal_tx = crate::app::SIGNAL_TX
        .lock()
        .unwrap()
        .as_ref()
        .cloned()
        .expect("app hasn't been initialized");

    thread::spawn(move || {
        while let Ok(()) = rx.recv() {
            thread::sleep(Duration::from_secs(1));
            // Handle any other buildup, but don't wait.
            while let Ok(()) = rx.try_recv() {}
            let _ = signal_tx.send(None);
        }
    });

    tx
}
