/// A declared input path and its public validation code.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldError {
    pub path: String,
    pub code: String,
}

pub(crate) fn valid_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase())
}

pub(crate) fn valid_message(message: &str) -> bool {
    message.len() <= 1024
        && !message
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
}

pub(crate) fn valid_fields(fields: &[FieldError], declared: Option<&[&str]>) -> bool {
    fields.len() <= 32
        && fields.iter().all(|field| {
            valid_error_code(&field.code)
                && path_shape(&field.path).is_some_and(|shape| {
                    declared.is_none_or(|paths| paths.contains(&shape.as_str()))
                })
        })
}

fn path_shape(mut path: &str) -> Option<String> {
    if path.len() > 256 {
        return None;
    }
    let mut shape = String::with_capacity(path.len());
    loop {
        let boundary = path.find(['.', '[']).unwrap_or(path.len());
        let (field, rest) = path.split_at(boundary);
        if !field.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
            || field.split('_').any(|part| {
                part.is_empty()
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
        {
            return None;
        }
        shape.push_str(field);
        path = rest;
        while let Some(rest) = path.strip_prefix('[') {
            let (index, suffix) = rest.split_once(']')?;
            if (index.len() > 1 && index.starts_with('0'))
                || !index.bytes().all(|b| b.is_ascii_digit())
                || index.parse::<u32>().is_err()
            {
                return None;
            }
            shape.push_str("[]");
            path = suffix;
        }
        if path.is_empty() {
            return Some(shape);
        }
        path = path.strip_prefix('.')?;
        shape.push('.');
    }
}
