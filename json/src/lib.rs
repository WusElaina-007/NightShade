/*
 * This file is part of NightShade (a hardened fork of sqlerrorthing/ShadowSniff)
 *
 * MIT License
 *
 * Copyright (c) 2025 sqlerrorthing
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#![no_std]

extern crate alloc;
mod parser;
mod tokenize;

use crate::parser::{TokenParseError, parse_tokens};
use crate::tokenize::{TokenizeError, tokenize};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};

#[cfg_attr(test, derive(Debug))]
#[derive(Clone)]
pub enum Value {
    Null,
    Boolean(bool),
    String(Arc<str>),
    Number(f64),
    Array(Vec<Value>),
    Object(Arc<BTreeMap<String, Value>>),
}

impl Value {
    pub fn as_null(&self) -> Option<()> {
        if let Value::Null = self {
            Some(())
        } else {
            None
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let Self::Boolean(val) = self {
            Some(*val)
        } else {
            None
        }
    }

    pub fn as_string(&self) -> Option<Arc<str>> {
        if let Self::String(val) = self {
            Some(val.clone())
        } else {
            None
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        if let Self::Number(val) = self {
            Some(*val)
        } else {
            None
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        if let Self::Array(val) = self {
            Some(val)
        } else {
            None
        }
    }

    pub fn as_object(&self) -> Option<Arc<BTreeMap<String, Value>>> {
        if let Self::Object(val) = self {
            Some(val.clone())
        } else {
            None
        }
    }

    pub fn get(&self, key: impl Into<Key>) -> Option<Value> {
        match (self, key.into()) {
            (Value::Object(map), Key::Str(k)) => map.get(&k).cloned(),
            (Value::Array(arr), Key::Idx(i)) => arr.get(i).cloned(),
            _ => None,
        }
    }
}

pub enum Key {
    Str(String),
    Idx(usize),
}

impl From<&str> for Key {
    fn from(s: &str) -> Self {
        if let Ok(i) = s.parse::<usize>() {
            Key::Idx(i)
        } else {
            Key::Str(s.to_string())
        }
    }
}

impl From<usize> for Key {
    fn from(i: usize) -> Self {
        Key::Idx(i)
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Value::Null => {
                write!(f, "null")
            }
            Value::Boolean(value) => {
                write!(f, "{value}")
            }
            Value::String(value) => {
                write!(f, "{value}")
            }
            Value::Number(value) => {
                write!(f, "{value}")
            }
            Value::Array(value) => {
                write!(f, "[array {}]", value.len())
            }
            Value::Object(_) => {
                write!(f, "{{object Object}}")
            }
        }
    }
}

pub fn parse_str<S>(input: S) -> Result<Value, ParseError>
where
    S: AsRef<str>,
{
    let tokens = tokenize(input)?;
    let value = parse_tokens(&tokens, &mut 0, 0)?;
    Ok(value)
}

pub fn parse(input: &[u8]) -> Result<Value, ParseError> {
    parse_str(str::from_utf8(input).map_err(|_| ParseError::InvalidEncoding)?)
}

#[cfg_attr(any(test, debug_assertions), derive(Debug))]
pub enum ParseError {
    TokenizeError(TokenizeError),
    ParseError(TokenParseError),
    InvalidEncoding,
}

impl From<TokenParseError> for ParseError {
    fn from(err: TokenParseError) -> Self {
        Self::ParseError(err)
    }
}

impl From<TokenizeError> for ParseError {
    fn from(err: TokenizeError) -> Self {
        Self::TokenizeError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    extern crate std;

    #[test]
    fn test_parse_str() {
        let input = r#"
        {"id":"***","username":"***","avatar":null,"discriminator":"0","public_flags":0,"flags":0,"banner":null,"accent_color":null,"global_name":"***","avatar_decoration_data":null,"collectibles":null,"banner_color":null,"clan":null,"primary_guild":null,"mfa_enabled":false,"locale":"***","premium_type":0,"email":"***","verified":true,"phone":null,"nsfw_allowed":true,"linked_users":[],"bio":"","authenticator_types":[],"age_verification_status":1}
        "#;

        match parse_str(input) {
            Ok(result) => {
                std::dbg!(&result);
            }
            Err(err) => panic!("parse_str failed: {:?}", err),
        }
    }

    // Regression: an empty or truncated HTTP body used to panic with an
    // index-out-of-bounds in the parser/tokenizer instead of returning Err.
    #[test]
    fn test_empty_and_truncated_input_returns_err() {
        assert!(parse_str("").is_err());
        assert!(parse_str("{").is_err());
        assert!(parse_str("{\"a\":").is_err());
        assert!(parse_str("[1,").is_err());
        assert!(parse_str("\"unclosed").is_err());
        assert!(parse_str("nul").is_err());
        assert!(parse_str("tru").is_err());
        assert!(parse_str("fals").is_err());
    }

    // Regression: surrogate pairs (any emoji from the Telegram/Discord APIs)
    // used to abort the whole parse with InvalidHexValue.
    #[test]
    fn test_surrogate_pairs_and_lone_surrogates() {
        let emoji = parse_str(r#""\ud83d\ude00""#).expect("surrogate pair must parse");
        assert_eq!(emoji.as_string().unwrap().len(), 4); // U+1F600 = 4 UTF-8 bytes

        let lone = parse_str(r#""\ud83d""#).expect("lone surrogate must not abort");
        assert_eq!(
            lone.as_string().unwrap().chars().next().unwrap(),
            '\u{FFFD}'
        );
    }

    // Regression: deep nesting used to overflow the stack (panic = abort).
    #[test]
    fn test_depth_limit_is_enforced() {
        let deep = format!("{}{}", "[".repeat(500), "]".repeat(500));
        assert!(parse_str(&deep).is_err());

        let ok_depth = format!("{}{}", "[".repeat(64), "]".repeat(64));
        assert!(parse_str(&ok_depth).is_ok());
    }
}
