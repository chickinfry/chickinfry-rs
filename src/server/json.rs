use serde::{Deserialize, Deserializer, de};
use serde_json::{Map, Value};
use std::fmt;

pub(super) struct Input(pub Value);

impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct InputVisitor;

        impl<'de> de::Visitor<'de> for InputVisitor {
            type Value = Input;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Input, E> {
                Ok(Input(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Input, E> {
                Ok(Input(Value::Number(value.into())))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Input, E> {
                Ok(Input(Value::Number(value.into())))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Input, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| Input(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Input, E> {
                self.visit_string(value.to_owned())
            }

            fn visit_string<E: de::Error>(self, value: String) -> Result<Input, E> {
                Ok(Input(Value::String(value)))
            }

            fn visit_unit<E: de::Error>(self) -> Result<Input, E> {
                Ok(Input(Value::Null))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut access: A) -> Result<Input, A::Error> {
                let mut values = Vec::new();
                while let Some(Input(value)) = access.next_element()? {
                    values.push(value);
                }
                Ok(Input(Value::Array(values)))
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut access: A) -> Result<Input, A::Error> {
                let mut values = Map::new();
                while let Some((key, Input(value))) = access.next_entry::<String, Input>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(Input(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(InputVisitor)
    }
}

// serde_json can stop at a depth or numeric limit before reaching a syntax error.
// Check the complete grammar without constructing values or recursing.
pub(super) fn is_valid(mut input: &[u8]) -> bool {
    if std::str::from_utf8(input).is_err() {
        return false;
    }
    enum State {
        Value,
        ArrayFirst,
        ArrayValue,
        ArrayEnd,
        ObjectFirst,
        ObjectKey,
        ObjectColon,
        ObjectEnd,
        End,
    }
    let mut pending = vec![State::End, State::Value];
    while let Some(state) = pending.pop() {
        while matches!(input.first(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            input = &input[1..];
        }
        match state {
            State::Value => match input.first() {
                Some(b'{') => {
                    input = &input[1..];
                    pending.push(State::ObjectFirst);
                }
                Some(b'[') => {
                    input = &input[1..];
                    pending.push(State::ArrayFirst);
                }
                Some(b'"') => {
                    if !string(&mut input) {
                        return false;
                    }
                }
                Some(b'-' | b'0'..=b'9') => {
                    if !number(&mut input) {
                        return false;
                    }
                }
                _ => {
                    let literal = [b"true".as_slice(), b"false", b"null"]
                        .into_iter()
                        .find_map(|literal| input.strip_prefix(literal));
                    match literal {
                        Some(rest) => input = rest,
                        None => return false,
                    }
                }
            },
            State::ArrayFirst if input.first() == Some(&b']') => input = &input[1..],
            State::ArrayFirst | State::ArrayValue => {
                pending.push(State::ArrayEnd);
                pending.push(State::Value);
            }
            State::ArrayEnd => match input {
                [b']', rest @ ..] => input = rest,
                [b',', rest @ ..] => {
                    input = rest;
                    pending.push(State::ArrayValue);
                }
                _ => return false,
            },
            State::ObjectFirst if input.first() == Some(&b'}') => input = &input[1..],
            State::ObjectFirst | State::ObjectKey => {
                if !string(&mut input) {
                    return false;
                }
                pending.push(State::ObjectColon);
            }
            State::ObjectColon => match input {
                [b':', rest @ ..] => {
                    input = rest;
                    pending.push(State::ObjectEnd);
                    pending.push(State::Value);
                }
                _ => return false,
            },
            State::ObjectEnd => match input {
                [b'}', rest @ ..] => input = rest,
                [b',', rest @ ..] => {
                    input = rest;
                    pending.push(State::ObjectKey);
                }
                _ => return false,
            },
            State::End => return input.is_empty(),
        }
    }
    false
}

fn string(input: &mut &[u8]) -> bool {
    let Some(mut rest) = input.strip_prefix(b"\"") else {
        return false;
    };
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        match byte {
            b'"' => {
                *input = rest;
                return true;
            }
            b'\\' => match rest {
                [
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't',
                    tail @ ..,
                ] => {
                    rest = tail;
                }
                [b'u', a, b, c, d, tail @ ..]
                    if [a, b, c, d].iter().all(|byte| byte.is_ascii_hexdigit()) =>
                {
                    rest = tail;
                }
                _ => return false,
            },
            0..=0x1f => return false,
            _ => {}
        }
    }
    false
}

fn number(input: &mut &[u8]) -> bool {
    let mut rest = input.strip_prefix(b"-").unwrap_or(input);
    match rest {
        [b'0', tail @ ..] => rest = tail,
        [b'1'..=b'9', ..] => {
            while matches!(rest.first(), Some(b'0'..=b'9')) {
                rest = &rest[1..];
            }
        }
        _ => return false,
    }
    if let Some(tail) = rest.strip_prefix(b".") {
        rest = tail;
        if !matches!(rest.first(), Some(b'0'..=b'9')) {
            return false;
        }
        while matches!(rest.first(), Some(b'0'..=b'9')) {
            rest = &rest[1..];
        }
    }
    if matches!(rest.first(), Some(b'e' | b'E')) {
        rest = &rest[1..];
        if matches!(rest.first(), Some(b'+' | b'-')) {
            rest = &rest[1..];
        }
        if !matches!(rest.first(), Some(b'0'..=b'9')) {
            return false;
        }
        while matches!(rest.first(), Some(b'0'..=b'9')) {
            rest = &rest[1..];
        }
    }
    *input = rest;
    true
}

#[cfg(test)]
mod tests {
    use super::is_valid;

    #[test]
    fn grammar_is_independent_of_value_limits() {
        for input in [
            r#" {"a": [true, false, null, {}, [], -0, 1.25e+999, -1E-999]} "#,
            r#"{"a":"\"\\\/\b\f\n\r\t\u0000\uD800","a":"é"}"#,
            "\r\n\t 1e999 ",
            "false",
            "\"\u{7f}\"",
        ] {
            assert!(is_valid(input.as_bytes()), "{input:?}");
        }
        for input in [
            "",
            " ",
            "{",
            "[",
            "[1,]",
            "[1 2]",
            "{\"a\":1,}",
            "{1:2}",
            "{\"a\" 1}",
            "{\"a\":}",
            "{}{}",
            "[}",
            "{]",
            "truex",
            "False",
            "nul",
            "NaN",
            "Infinity",
            "+1",
            "01",
            "-01",
            "-",
            "1.",
            "1e",
            "1e+",
            ".1",
            "\"",
            "\"\\",
            "\"\\x\"",
            "\"\\u123\"",
            "\"\\u123g\"",
            "\"\n\"",
            "\u{b}0",
            "\u{feff}{}",
        ] {
            assert!(!is_valid(input.as_bytes()), "{input:?}");
        }
        assert!(!is_valid(b"\"\xff\""));
    }
}
