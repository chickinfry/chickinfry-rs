use std::fmt;
use std::io::BufRead;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

pub const MAX_LINE: usize = 16 << 20;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Error {
    pub kind: String,
    pub code: Option<String>,
    pub http_status: Option<u16>,
    pub outcome_unknown: bool,
}

impl Error {
    pub fn driver(code: &str) -> Self {
        Self {
            kind: if code == "unimplemented" {
                "unimplemented"
            } else {
                "driver"
            }
            .into(),
            code: Some(code.into()),
            http_status: None,
            outcome_unknown: false,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub command: String,
    pub args: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub id: String,
    pub result: Value,
    pub error: Value,
}

pub enum Message {
    Request(Request),
    Response(Response),
}

/// Rejects duplicate keys at every depth before converting to a JSON value.
struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Json;
        impl<'de> Visitor<'de> for Json {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| Unique(Value::Number(v)))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let Unique(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Json)
    }
}

pub fn json(line: &[u8]) -> Result<Value> {
    if line.len() > MAX_LINE {
        return Err(Error::driver("protocol_violation"));
    }
    serde_json::from_slice::<Unique>(line)
        .map(|v| v.0)
        .map_err(|_| Error::driver("protocol_violation"))
}

pub fn message(line: &[u8]) -> Result<Message> {
    let value = json(line)?;
    if value.get("command").is_some() {
        let request: Request =
            serde_json::from_value(value).map_err(|_| Error::driver("protocol_violation"))?;
        if !id(&request.id, "c:") || !request.args.is_object() {
            return Err(Error::driver("protocol_violation"));
        }
        Ok(Message::Request(request))
    } else {
        let response: Response =
            serde_json::from_value(value).map_err(|_| Error::driver("protocol_violation"))?;
        if !id(&response.id, "d:") || response.result.is_null() == response.error.is_null() {
            return Err(Error::driver("protocol_violation"));
        }
        if !response.result.is_null() && !response.result.is_object() {
            return Err(Error::driver("protocol_violation"));
        }
        if !response.error.is_null() {
            let object = response
                .error
                .as_object()
                .ok_or_else(|| Error::driver("protocol_violation"))?;
            if ["kind", "code", "httpStatus", "outcomeUnknown"]
                .iter()
                .any(|key| !object.contains_key(*key))
            {
                return Err(Error::driver("protocol_violation"));
            }
            let error: Error = serde_json::from_value(response.error.clone())
                .map_err(|_| Error::driver("protocol_violation"))?;
            if !["sdk", "driver", "unimplemented"].contains(&error.kind.as_str()) {
                return Err(Error::driver("protocol_violation"));
            }
        }
        Ok(Message::Response(response))
    }
}

pub fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"_-.:/".contains(&v))
}

fn id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix) && value.len() > 2 && name(value)
}

/// Reads at most one bounded line; EOF in a nonempty frame is a violation.
pub fn line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>> {
    bounded_line(reader, MAX_LINE + 1)
}

pub fn bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .map_err(|_| Error::driver("driver_failed"))?;
        if buffer.is_empty() {
            return if data.is_empty() {
                Ok(None)
            } else {
                Err(Error::driver("protocol_violation"))
            };
        }
        let end = buffer.iter().position(|v| *v == b'\n');
        let count = end.unwrap_or(buffer.len());
        if data.len() + count + 1 > limit {
            return Err(Error::driver("protocol_violation"));
        }
        data.extend_from_slice(&buffer[..count]);
        reader.consume(count + usize::from(end.is_some()));
        if end.is_some() {
            return Ok(Some(data));
        }
    }
}

pub fn fields(args: &Value, allowed: &[&str], common: bool) -> Result<()> {
    let object = args
        .as_object()
        .ok_or_else(|| Error::driver("invalid_args"))?;
    if object.keys().any(|key| {
        !allowed.contains(&key.as_str())
            && !(common && ["caseId", "timeoutMs"].contains(&key.as_str()))
    }) {
        return Err(Error::driver("protocol_violation"));
    }
    Ok(())
}

pub fn string<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::driver("invalid_args"))
}

pub fn reference<'a>(args: &'a Value, key: &str) -> Result<&'a str> {
    let v = string(args, key)?;
    if !name(v) {
        return Err(Error::driver("invalid_args"));
    }
    Ok(v)
}

pub fn millis(args: &Value, key: &str) -> Result<u64> {
    args.get(key)
        .and_then(Value::as_u64)
        .filter(|v| *v > 0 && *v <= u32::MAX as u64)
        .ok_or_else(|| Error::driver("invalid_args"))
}
