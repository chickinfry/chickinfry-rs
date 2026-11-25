use time::{
    OffsetDateTime, SignedDuration, format_description::well_known::Rfc3339,
    macros::format_description,
};

pub(crate) fn parse_rfc3339(text: &str) -> Option<OffsetDateTime> {
    // time also accepts arbitrary one-byte date/time separators.
    if !matches!(text.as_bytes().get(10), Some(b'T' | b't' | b' ')) {
        return None;
    }
    let timestamp = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    if text.as_bytes().get(17..19) == Some(b"60") {
        // Preserve the Unix instant and fraction instead of time's leap-second clamp.
        let mut preceding = text.to_owned();
        preceding.replace_range(17..19, "59");
        return OffsetDateTime::parse(&preceding, &Rfc3339)
            .ok()?
            .checked_add(SignedDuration::SECOND);
    }
    Some(timestamp)
}

pub(crate) fn parse_postgres_timestamp(text: &str) -> Option<OffsetDateTime> {
    parse_rfc3339(text).or_else(|| {
        if text.as_bytes().get(10) != Some(&b' ') {
            return None;
        }
        let offset_start = 19 + text.get(19..)?.find(['+', '-'])?;
        let (date_time, offset) = text.split_at(offset_start);
        let normalized = match offset.len() {
            3 => format!("{date_time}{offset}:00"),
            5 => format!("{date_time}{}:{}", offset.get(..3)?, offset.get(3..)?),
            _ => return None,
        };
        parse_rfc3339(&normalized)
    })
}

pub(crate) fn format_unix_millis(millis: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .ok()?
        .format(format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
        ))
        .ok()
}
