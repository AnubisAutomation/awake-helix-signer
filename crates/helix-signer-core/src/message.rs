//! User-facing messages with a stable code.
//!
//! Every progress line and every [`Error`](crate::Error) carries a
//! [`Message`]: a stable `code`, the values it names (`params`) and the
//! English `text` the command line prints. The app translates the code with
//! its own tables (`core.<code>` keys) and falls back to the English text,
//! so the command line stays English while the app follows the selected
//! language, and a language switch re-renders what is already shown.
//!
//! Build messages with [`msg!`](crate::msg): the template is an ordinary
//! `format!` string whose named arguments become the params.
//!
//! A message of the website (an HTTP error answer) has the code `website`
//! and carries the website's own texts and code in [`SiteText`].

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;
use serde_json::{Map, Value};

/// One value a message names: a text, or another message (a cause, a
/// website answer) that the app translates on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Param {
    /// A value shown as is (an address, a number, a URL, a file name).
    Text(String),
    /// A nested message.
    Message(Box<Message>),
}

/// What the website said in an error answer: its Traditional Chinese text,
/// its English text and its stable code with parameters (newer websites).
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteText {
    /// HTTP status.
    pub status: u16,
    /// The website's code (``plan.expired`` ...), "" when it sent none.
    pub code: String,
    /// The website's parameters for its code.
    pub params: Map<String, Value>,
    /// ``error``: the website's own language (Traditional Chinese).
    pub zh: String,
    /// ``errorEn``, "" when the website sent none.
    pub en: String,
}

/// A user-facing message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Message {
    /// Stable code, e.g. ``flow.wrongKey``; a bare error kind (``plan``,
    /// ``network`` ...) for a message that has no code of its own.
    pub code: &'static str,
    /// Named values of the message.
    pub params: BTreeMap<&'static str, Param>,
    /// English text (what the command line prints).
    pub text: String,
    /// The website's answer, for code ``website``.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub site: Option<Box<SiteText>>,
}

impl Message {
    /// A message with a code, its params and its English text.
    pub fn new(code: &'static str, params: BTreeMap<&'static str, Param>, text: String) -> Self {
        Self { code, params, text, site: None }
    }

    /// A message without a code of its own (``code`` is a bare kind).
    pub fn plain(code: &'static str, text: impl Into<String>) -> Self {
        Self { code, params: BTreeMap::new(), text: text.into(), site: None }
    }

    /// The website's error answer.
    pub fn website(site: SiteText, text: String) -> Self {
        Self { code: "website", params: BTreeMap::new(), text, site: Some(Box::new(site)) }
    }

    /// A text param of this message.
    pub fn param(&self, name: &str) -> Option<&str> {
        match self.params.get(name) {
            Some(Param::Text(text)) => Some(text),
            _ => None,
        }
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Values a message may name.
pub trait ToParam {
    /// The value as a message param.
    fn to_param(&self) -> Param;
}

macro_rules! text_params {
    ($($type:ty),*) => {
        $(impl ToParam for $type {
            fn to_param(&self) -> Param {
                Param::Text(self.to_string())
            }
        })*
    };
}
text_params!(str, String, u8, u16, u32, u64, usize, i32, i64, crate::address::Address, std::path::Display<'_>, ruint::aliases::U256);

impl ToParam for Message {
    fn to_param(&self) -> Param {
        Param::Message(Box::new(self.clone()))
    }
}

impl ToParam for crate::error::Error {
    fn to_param(&self) -> Param {
        Param::Message(Box::new(self.msg().clone()))
    }
}

impl<T: ToParam + ?Sized> ToParam for &T {
    fn to_param(&self) -> Param {
        (**self).to_param()
    }
}

/// Build a [`Message`]: `msg!("flow.wrongKey", "Wrong key: {key} ...", key = address)`.
///
/// The template is a `format!` string; every named argument is used by it
/// and becomes a param (a [`Message`] or [`Error`](crate::Error) argument
/// becomes a nested message the app translates on its own).
#[macro_export]
macro_rules! msg {
    ($code:literal, $template:literal $(, $name:ident = $value:expr)* $(,)?) => {{
        $( #[allow(clippy::redundant_locals)] let $name = $value; )*
        #[allow(unused_mut)]
        let mut params = ::std::collections::BTreeMap::new();
        $( params.insert(stringify!($name), $crate::message::ToParam::to_param(&$name)); )*
        $crate::message::Message::new($code, params, format!($template $(, $name = $name)*))
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_and_text() {
        let inner = crate::msg!("chain.reverted", "Transaction {tx} reverted on chain.", tx = "0xab");
        let outer = crate::msg!("flow.withTransaction", "{cause} (transaction {tx})", cause = inner.clone(), tx = String::from("0xab"));
        assert_eq!(outer.text, "Transaction 0xab reverted on chain. (transaction 0xab)");
        assert_eq!(outer.param("tx"), Some("0xab"));
        assert_eq!(outer.params.get("cause"), Some(&Param::Message(Box::new(inner))));
        let json = serde_json::to_value(&outer).unwrap();
        assert_eq!(json["code"], "flow.withTransaction");
        assert_eq!(json["params"]["tx"], "0xab");
        assert_eq!(json["params"]["cause"]["code"], "chain.reverted");
        assert!(json.get("site").is_none());
    }
}
