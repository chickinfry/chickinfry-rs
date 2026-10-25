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
