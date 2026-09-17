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

use crate::Value;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::tokenize::Token;

pub type ParseResult = Result<Value, TokenParseError>;

/// Hard cap on nested arrays/objects. The parser is recursive descent, so an
/// unbounded host (or a hostile endpoint) could previously overflow the stack
/// with a body like `[[[[[...`.
const MAX_NESTING_DEPTH: usize = 128;

pub fn parse_tokens(tokens: &[Token], index: &mut usize, depth: usize) -> ParseResult {
    if depth > MAX_NESTING_DEPTH {
        return Err(TokenParseError::DepthLimitExceeded);
    }

    // Bounds check: an empty or truncated token stream used to panic here.
    let Some(token) = tokens.get(*index) else {
        return Err(TokenParseError::ExpectedValue);
    };

    if matches!(
        token,
        Token::Null | Token::False | Token::True | Token::Number(_) | Token::String(_)
    ) {
        *index += 1
    }
    match token {
        Token::Null => Ok(Value::Null),
        Token::False => Ok(Value::Boolean(false)),
        Token::True => Ok(Value::Boolean(true)),
        Token::Number(number) => Ok(Value::Number(*number)),
        Token::String(string) => parse_string(string),
        Token::LeftBracket => parse_array(tokens, index, depth),
        Token::LeftBrace => parse_object(tokens, index, depth),
        _ => Err(TokenParseError::ExpectedValue),
    }
}

fn parse_string(input: &str) -> ParseResult {
    let unescaped = unescape_string(input)?;
    Ok(Value::String(Arc::from(unescaped)))
}

fn unescape_string(input: &str) -> Result<String, TokenParseError> {
    let mut output = String::new();

    let mut is_escaping = false;
    let mut chars = input.chars();
    while let Some(next_char) = chars.next() {
        if is_escaping {
            match next_char {
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                'b' => output.push('\u{8}'),
                'f' => output.push('\u{12}'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                'u' => {
                    let first = parse_hex_quad(&mut chars)?;

                    let code_point = if (0xD800..=0xDBFF).contains(&first) {
                        // High surrogate: must be followed by \uDC00-\uDFFF.
                        // Previously ANY surrogate aborted the whole parse,
                        // which broke real-world payloads (emoji!) from the
                        // Telegram/Discord APIs.
                        if chars.next() == Some('\\') && chars.next() == Some('u') {
                            let second = parse_hex_quad(&mut chars)?;

                            if (0xDC00..=0xDFFF).contains(&second) {
                                0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)
                            } else {
                                // Mismatched pair: keep parsing with replacement chars.
                                output.push('\u{FFFD}');
                                output.push(char::from_u32(second).unwrap_or('\u{FFFD}'));
                                is_escaping = false;
                                continue;
                            }
                        } else {
                            // Lone high surrogate: replacement char, keep going.
                            output.push('\u{FFFD}');
                            is_escaping = false;
                            continue;
                        }
                    } else if (0xDC00..=0xDFFF).contains(&first) {
                        // Lone low surrogate: replacement char, keep going.
                        output.push('\u{FFFD}');
                        is_escaping = false;
                        continue;
                    } else {
                        first
                    };

                    output.push(char::from_u32(code_point).unwrap_or('\u{FFFD}'));
                }
                _ => output.push(next_char),
            }
            is_escaping = false;
        } else if next_char == '\\' {
            is_escaping = true;
        } else {
            output.push(next_char);
        }
    }
    Ok(output)
}

fn parse_hex_quad(chars: &mut core::str::Chars) -> Result<u32, TokenParseError> {
    let mut sum = 0u32;

    for i in 0..4 {
        let next_char = chars.next().ok_or(TokenParseError::UnfinishedEscape)?;
        let digit = next_char
            .to_digit(16)
            .ok_or(TokenParseError::InvalidHexValue)?;
        sum += (16u32).pow(3 - i) * digit;
    }

    Ok(sum)
}

fn parse_array(tokens: &[Token], index: &mut usize, depth: usize) -> ParseResult {
    debug_assert!(tokens[*index] == Token::LeftBracket);

    let mut array: Vec<Value> = Vec::new();
    loop {
        *index += 1;

        // Bounds checks: truncated input ("[1,") used to panic here.
        let Some(token) = tokens.get(*index) else {
            return Err(TokenParseError::UnclosedBracket);
        };

        if *token == Token::RightBracket {
            break;
        }

        let value = parse_tokens(tokens, index, depth + 1)?;
        array.push(value);

        let Some(token) = tokens.get(*index) else {
            return Err(TokenParseError::UnclosedBracket);
        };

        match token {
            Token::Comma => {}
            Token::RightBracket => break,
            _ => return Err(TokenParseError::ExpectedComma),
        }
    }
    *index += 1;

    Ok(Value::Array(array))
}

fn parse_object(tokens: &[Token], index: &mut usize, depth: usize) -> ParseResult {
    debug_assert!(tokens[*index] == Token::LeftBrace);

    let mut map = BTreeMap::new();
    loop {
        *index += 1;

        // Bounds checks: truncated input ("{", "{\"a\":") used to panic here.
        let Some(token) = tokens.get(*index) else {
            return Err(TokenParseError::UnclosedBrace);
        };

        if *token == Token::RightBrace {
            break;
        }

        if let Token::String(s) = token {
            *index += 1;

            let Some(colon) = tokens.get(*index) else {
                return Err(TokenParseError::UnclosedBrace);
            };

            if *colon == Token::Colon {
                *index += 1;
                let key = unescape_string(s)?;
                let value = parse_tokens(tokens, index, depth + 1)?;
                map.insert(key, value);
            } else {
                return Err(TokenParseError::ExpectedColon);
            }

            let Some(token) = tokens.get(*index) else {
                return Err(TokenParseError::UnclosedBrace);
            };

            match token {
                Token::Comma => {}
                Token::RightBrace => break,
                _ => return Err(TokenParseError::ExpectedComma),
            }
        } else {
            return Err(TokenParseError::ExpectedProperty);
        }
    }
    *index += 1;

    Ok(Value::Object(Arc::from(map)))
}

#[derive(Debug, PartialEq)]
pub enum TokenParseError {
    UnclosedBracket,
    UnclosedBrace,

    UnfinishedEscape,
    InvalidHexValue,
    InvalidCodePointValue,

    ExpectedColon,
    ExpectedComma,
    ExpectedValue,
    ExpectedProperty,

    NeedsComma,
    TrailingComma,

    DepthLimitExceeded,
}
